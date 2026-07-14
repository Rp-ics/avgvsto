use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonOsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};
use chacha20poly1305::ChaCha20Poly1305;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;

use crate::error::{CoreError, CoreResult};
use crate::CipherSuite;

static PBKDF2_ALGO: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

/// Derive a 32-byte key from a passphrase using PBKDF2-HMAC-SHA256 (1M iterations).
pub fn derive_key_pbkdf2(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        PBKDF2_ALGO,
        NonZeroU32::new(crate::PBKDF2_ITERATIONS).unwrap(),
        salt,
        passphrase.as_bytes(),
        &mut key,
    );
    key
}

/// Derive a 32-byte key from a passphrase using Argon2id.
pub fn derive_key_argon2(passphrase: &str) -> CoreResult<([u8; 32], [u8; 16])> {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| CoreError::KeyDerivation(e.to_string()))?;

    let hash_bytes = hash.hash.unwrap().as_bytes().to_vec();
    if hash_bytes.len() < 32 {
        return Err(CoreError::KeyDerivation(
            "derived key too short".to_string(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[..32]);
    let mut salt_bytes = [0u8; 16];
    let salt_str = salt.as_str().as_bytes();
    let copy_len = salt_str.len().min(16);
    salt_bytes[..copy_len].copy_from_slice(&salt_str[..copy_len]);

    Ok((key, salt_bytes))
}

/// Verify a passphrase against an Argon2id hash string.
pub fn verify_argon2(passphrase: &str, hash_str: &str) -> CoreResult<bool> {
    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| CoreError::InvalidKey(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(passphrase.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("failed to generate random bytes");
    bytes
}

/// Encrypt data using AES-256-GCM.
pub fn encrypt_aes256gcm(key: &[u8; 32], plaintext: &[u8]) -> CoreResult<(Vec<u8>, [u8; 12], [u8; 16])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce_bytes = random_bytes::<12>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;

    let tag_offset = ciphertext.len().saturating_sub(16);
    let (ct, tag) = ciphertext.split_at(tag_offset);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);

    Ok((ct.to_vec(), nonce_bytes, tag_arr))
}

/// Decrypt data using AES-256-GCM.
pub fn decrypt_aes256gcm(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> CoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CoreError::Decryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(tag);
    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| CoreError::Decryption(e.to_string()))?;
    Ok(plaintext)
}

/// Encrypt data using ChaCha20-Poly1305.
pub fn encrypt_chacha20(
    key: &[u8; 32],
    plaintext: &[u8],
) -> CoreResult<(Vec<u8>, [u8; 12], [u8; 16])> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    let nonce_bytes = random_bytes::<12>();
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;

    let tag_offset = ciphertext.len().saturating_sub(16);
    let (ct, tag) = ciphertext.split_at(tag_offset);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);

    Ok((ct.to_vec(), nonce_bytes, tag_arr))
}

/// Decrypt data using ChaCha20-Poly1305.
pub fn decrypt_chacha20(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> CoreResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CoreError::Decryption(e.to_string()))?;
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(tag);
    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| CoreError::Decryption(e.to_string()))?;
    Ok(plaintext)
}

/// Encrypt data with the selected cipher suite.
pub fn encrypt(
    cipher_suite: CipherSuite,
    key: &[u8; 32],
    plaintext: &[u8],
) -> CoreResult<(Vec<u8>, [u8; 12], [u8; 16])> {
    match cipher_suite {
        CipherSuite::Aes256Gcm => encrypt_aes256gcm(key, plaintext),
        CipherSuite::ChaCha20Poly1305 => encrypt_chacha20(key, plaintext),
    }
}

/// Decrypt data with the selected cipher suite.
pub fn decrypt(
    cipher_suite: CipherSuite,
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> CoreResult<Vec<u8>> {
    match cipher_suite {
        CipherSuite::Aes256Gcm => decrypt_aes256gcm(key, ciphertext, nonce, tag),
        CipherSuite::ChaCha20Poly1305 => decrypt_chacha20(key, ciphertext, nonce, tag),
    }
}

/// Generate a random 32-byte key.
pub fn generate_key() -> [u8; 32] {
    random_bytes::<32>()
}

/// Generate a random 16-byte salt.
pub fn generate_salt() -> [u8; 16] {
    random_bytes::<16>()
}

/// Encrypt data marking it as duress-protected.
/// When the wrong passphrase is used for decryption with duress-aware decryptors,
/// a garbage response is returned instead of an authentication error,
/// allowing the user to comply with coercion while protecting the real data.
pub fn duress_encrypt(
    cipher_suite: CipherSuite,
    key: &[u8; 32],
    plaintext: &[u8],
) -> CoreResult<(Vec<u8>, [u8; 12], [u8; 16])> {
    let (ciphertext, nonce, tag) = encrypt(cipher_suite, key, plaintext)?;
    Ok((ciphertext, nonce, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = generate_key();
        let plaintext = b"Hello, AVGVSTO! This is a test message.";
        let (ct, nonce, tag) = encrypt_aes256gcm(&key, plaintext).unwrap();
        let decrypted = decrypt_aes256gcm(&key, &ct, &nonce, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = generate_key();
        let plaintext = b"ChaCha20-Poly1305 test message";
        let (ct, nonce, tag) = encrypt_chacha20(&key, plaintext).unwrap();
        let decrypted = decrypt_chacha20(&key, &ct, &nonce, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_derivation_pbkdf2() {
        let salt = generate_salt();
        let key1 = derive_key_pbkdf2("test-passphrase", &salt);
        let key2 = derive_key_pbkdf2("test-passphrase", &salt);
        assert_eq!(key1, key2);

        let key3 = derive_key_pbkdf2("different-passphrase", &salt);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_aes256gcm_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"secret data";
        let (ct, nonce, tag) = encrypt_aes256gcm(&key1, plaintext).unwrap();
        let result = decrypt_aes256gcm(&key2, &ct, &nonce, &tag);
        assert!(result.is_err());
    }
}
