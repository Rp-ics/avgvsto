use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub resource: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for AuditEvent {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let action_str: String = row.try_get("action")?;
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            action: AuditAction::from(action_str.as_str()),
            resource: row.try_get("resource")?,
            details: row.try_get("details")?,
            ip_address: row.try_get("ip_address")?,
            user_agent: row.try_get("user_agent")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    UserRegistered,
    UserLoggedIn,
    UserLoggedOut,
    TokenRefreshed,
    TokenRevoked,
    FileEncrypted,
    FileDecrypted,
    FileVerified,
    KeyBound,
    KeyUnbound,
    KeyVerified,
    FileDeleted,
    ConfigChanged,
    AdminAction,
    FailedLogin,
    FailedDecrypt,
    RateLimitExceeded,
    InvalidToken,
    Unknown,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::UserRegistered => "user.registered",
            Self::UserLoggedIn => "user.logged_in",
            Self::UserLoggedOut => "user.logged_out",
            Self::TokenRefreshed => "token.refreshed",
            Self::TokenRevoked => "token.revoked",
            Self::FileEncrypted => "file.encrypted",
            Self::FileDecrypted => "file.decrypted",
            Self::FileVerified => "file.verified",
            Self::KeyBound => "key.bound",
            Self::KeyUnbound => "key.unbound",
            Self::KeyVerified => "key.verified",
            Self::FileDeleted => "file.deleted",
            Self::ConfigChanged => "config.changed",
            Self::AdminAction => "admin.action",
            Self::FailedLogin => "auth.failed_login",
            Self::FailedDecrypt => "crypto.failed_decrypt",
            Self::RateLimitExceeded => "rate_limit.exceeded",
            Self::InvalidToken => "auth.invalid_token",
            Self::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

impl From<&str> for AuditAction {
    fn from(s: &str) -> Self {
        match s {
            "user.registered" => Self::UserRegistered,
            "user.logged_in" => Self::UserLoggedIn,
            "user.logged_out" => Self::UserLoggedOut,
            "token.refreshed" => Self::TokenRefreshed,
            "token.revoked" => Self::TokenRevoked,
            "file.encrypted" => Self::FileEncrypted,
            "file.decrypted" => Self::FileDecrypted,
            "file.verified" => Self::FileVerified,
            "key.bound" => Self::KeyBound,
            "key.unbound" => Self::KeyUnbound,
            "key.verified" => Self::KeyVerified,
            "file.deleted" => Self::FileDeleted,
            "config.changed" => Self::ConfigChanged,
            "admin.action" => Self::AdminAction,
            "auth.failed_login" => Self::FailedLogin,
            "crypto.failed_decrypt" => Self::FailedDecrypt,
            "rate_limit.exceeded" => Self::RateLimitExceeded,
            "auth.invalid_token" => Self::InvalidToken,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub user_id: Option<Uuid>,
    pub action: Option<AuditAction>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuditEvent {
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub resource: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}
