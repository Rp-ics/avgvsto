use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::sync::Arc;
use uuid::Uuid;

use crate::TokenClaims;

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    access_expiry_secs: i64,
    refresh_expiry_secs: i64,
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: Arc::new(EncodingKey::from_secret(secret.as_bytes())),
            decoding_key: Arc::new(DecodingKey::from_secret(secret.as_bytes())),
            access_expiry_secs: 900,
            refresh_expiry_secs: 604800,
        }
    }

    pub fn refresh_expiry_secs(&self) -> i64 {
        self.refresh_expiry_secs
    }

    pub fn generate_token_pair(
        &self,
        user_id: Uuid,
        username: &str,
        role: &str,
    ) -> Result<TokenPair, JwtError> {
        let now = Utc::now().timestamp() as usize;

        let access_claims = TokenClaims {
            sub: user_id,
            username: username.to_string(),
            role: role.to_string(),
            exp: now + self.access_expiry_secs as usize,
            iat: now,
        };

        let access_token = encode(
            &Header::default(),
            &access_claims,
            &self.encoding_key,
        )
        .map_err(|e| JwtError::Encoding(e.to_string()))?;

        let refresh_claims = TokenClaims {
            sub: user_id,
            username: username.to_string(),
            role: role.to_string(),
            exp: now + self.refresh_expiry_secs as usize,
            iat: now,
        };

        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &self.encoding_key,
        )
        .map_err(|e| JwtError::Encoding(e.to_string()))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }

    pub fn validate_access_token(&self, token: &str) -> Result<TokenClaims, JwtError> {
        let validation = Validation::default();
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                _ => JwtError::Invalid(e.to_string()),
            })?;
        Ok(token_data.claims)
    }

    pub fn validate_refresh_token(&self, token: &str) -> Result<TokenClaims, JwtError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
                _ => JwtError::Invalid(e.to_string()),
            })?;
        Ok(token_data.claims)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("JWT encoding failed: {0}")]
    Encoding(String),
    #[error("JWT is invalid: {0}")]
    Invalid(String),
    #[error("JWT has expired")]
    Expired,
}

impl From<JwtError> for crate::AuthError {
    fn from(e: JwtError) -> Self {
        match e {
            JwtError::Expired => Self::TokenExpired,
            JwtError::Invalid(_msg) => Self::InvalidToken,
            JwtError::Encoding(msg) => Self::InternalError(msg),
        }
    }
}
