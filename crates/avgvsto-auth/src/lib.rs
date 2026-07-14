mod jwt;
mod password;
mod rate_limit;

pub use jwt::*;
pub use password::*;
pub use rate_limit::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use utoipa::ToSchema;

use avgvsto_audit::{AuditAction, AuditStore, CreateAuditEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for User {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            password_hash: row.try_get("password_hash")?,
            role: row.try_get("role")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user_id: Uuid,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,
    pub username: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

pub struct AuthService {
    pool: PgPool,
    jwt_service: JwtService,
    audit_store: AuditStore,
}

impl AuthService {
    pub fn new(pool: PgPool, jwt_service: JwtService) -> Self {
        Self {
            pool: pool.clone(),
            jwt_service,
            audit_store: AuditStore::new(pool),
        }
    }

    pub async fn register_user(
        &self,
        req: CreateUserRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<User, AuthError> {
        if req.username.len() < 3 || req.username.len() > 64 {
            return Err(AuthError::ValidationError(
                "username must be between 3 and 64 characters".to_string(),
            ));
        }
        if req.password.len() < 8 {
            return Err(AuthError::ValidationError(
                "password must be at least 8 characters".to_string(),
            ));
        }

        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users WHERE username = $1",
        )
        .bind(&req.username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?;

        if existing.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        let password_hash = hash_password(&req.password)
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (username, password_hash, role)
            VALUES ($1, $2, 'user')
            RETURNING id, username, password_hash, role, created_at, updated_at
            "#,
        )
        .bind(&req.username)
        .bind(&password_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?;

        self.audit_store
            .create_event(CreateAuditEvent {
                user_id: Some(user.id),
                action: AuditAction::UserRegistered,
                resource: Some(format!("user/{}", user.username)),
                details: serde_json::json!({}),
                ip_address,
                user_agent,
            })
            .await
            .ok();

        Ok(user)
    }

    pub async fn login(
        &self,
        req: LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AuthResponse, AuthError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE username = $1",
        )
        .bind(&req.username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?
        .ok_or(AuthError::InvalidCredentials)?;

        if !verify_password(&req.password, &user.password_hash)
            .map_err(|e| AuthError::InternalError(e.to_string()))?
        {
            self.audit_store
                .create_event(CreateAuditEvent {
                    user_id: Some(user.id),
                    action: AuditAction::FailedLogin,
                    resource: Some(format!("user/{}", user.username)),
                    details: serde_json::json!({"reason": "invalid_password"}),
                    ip_address,
                    user_agent,
                })
                .await
                .ok();

            return Err(AuthError::InvalidCredentials);
        }

        let tokens = self.jwt_service.generate_token_pair(user.id, &user.username, &user.role)?;

        // Store refresh token hash
        let token_hash = hash_string(&tokens.refresh_token);
        let expires_at = Utc::now()
            + chrono::Duration::seconds(self.jwt_service.refresh_expiry_secs());

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(user.id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?;

        self.audit_store
            .create_event(CreateAuditEvent {
                user_id: Some(user.id),
                action: AuditAction::UserLoggedIn,
                resource: Some(format!("user/{}", user.username)),
                details: serde_json::json!({}),
                ip_address,
                user_agent,
            })
            .await
            .ok();

        Ok(AuthResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 900,
            user_id: user.id,
            role: user.role,
        })
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AuthResponse, AuthError> {
        let claims = self.jwt_service.validate_refresh_token(refresh_token)?;

        // Verify token exists in DB and is not revoked
        let token_hash = hash_string(refresh_token);
        let stored: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT id FROM refresh_tokens WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()"#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?;

        stored.ok_or(AuthError::InvalidToken)?;

        // Revoke old token
        sqlx::query(
            r#"UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1"#,
        )
        .bind(&token_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?;

        // Generate new token pair
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(claims.sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?
        .ok_or(AuthError::InvalidToken)?;

        let tokens = self.jwt_service.generate_token_pair(user.id, &user.username, &user.role)?;

        // Store new refresh token
        let new_token_hash = hash_string(&tokens.refresh_token);
        let expires_at = Utc::now()
            + chrono::Duration::seconds(self.jwt_service.refresh_expiry_secs());

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(user.id)
        .bind(&new_token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Database(e))?;

        self.audit_store
            .create_event(CreateAuditEvent {
                user_id: Some(user.id),
                action: AuditAction::TokenRefreshed,
                resource: None,
                details: serde_json::json!({}),
                ip_address,
                user_agent,
            })
            .await
            .ok();

        Ok(AuthResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 900,
            user_id: user.id,
            role: user.role,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("validation error: {0}")]
    ValidationError(String),
    #[error("database error: {0}")]
    Database(sqlx::Error),
    #[error("internal error: {0}")]
    InternalError(String),
}

fn hash_string(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}
