use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

const MAX_PASSWORD_LENGTH: usize = 128;

/// Hash a password using Argon2id with default parameters.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(PasswordError::TooLong);
    }
    if password.is_empty() {
        return Err(PasswordError::Empty);
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::HashingError(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash string.
pub fn verify_password(password: &str, hash_str: &str) -> Result<bool, PasswordError> {
    if password.is_empty() {
        return Err(PasswordError::Empty);
    }

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| PasswordError::InvalidHash(e.to_string()))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password is too long (max {0} characters)", MAX_PASSWORD_LENGTH)]
    TooLong,
    #[error("password cannot be empty")]
    Empty,
    #[error("hashing failed: {0}")]
    HashingError(String),
    #[error("invalid hash format: {0}")]
    InvalidHash(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "my-secure-password-123!";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_empty_password_rejected() {
        assert!(hash_password("").is_err());
    }
}
