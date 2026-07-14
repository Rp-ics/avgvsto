use avgvsto_core::*;

#[test]
fn test_full_encrypt_decrypt_roundtrip_aes() {
    let key = generate_key();
    let plaintext = b"Integration test: full roundtrip with AES-256-GCM. This is a longer message to ensure everything works correctly with various data sizes.";

    let (ciphertext, nonce, tag) = encrypt(CipherSuite::Aes256Gcm, &key, plaintext).unwrap();
    let decrypted = decrypt(CipherSuite::Aes256Gcm, &key, &ciphertext, &nonce, &tag).unwrap();

    assert_eq!(decrypted, plaintext);
    assert_ne!(ciphertext, plaintext);
}

#[test]
fn test_full_encrypt_decrypt_roundtrip_chacha20() {
    let key = generate_key();
    let plaintext = b"ChaCha20-Poly1305 integration test payload";

    let (ciphertext, nonce, tag) = encrypt(CipherSuite::ChaCha20Poly1305, &key, plaintext).unwrap();
    let decrypted = decrypt(CipherSuite::ChaCha20Poly1305, &key, &ciphertext, &nonce, &tag).unwrap();

    assert_eq!(decrypted, plaintext);
    assert_ne!(ciphertext, plaintext);
}

#[test]
fn test_pbkdf2_key_derivation_and_encrypt() {
    let passphrase = "my-secure-passphrase-123!";
    let salt = generate_salt();
    let key = derive_key_pbkdf2(passphrase, &salt);

    let plaintext = b"Protected data secured with PBKDF2-derived key";
    let (ciphertext, nonce, tag) = encrypt(CipherSuite::Aes256Gcm, &key, plaintext).unwrap();
    let decrypted = decrypt(CipherSuite::Aes256Gcm, &key, &ciphertext, &nonce, &tag).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_argon2_key_derivation() {
    let passphrase = "argon2-test-passphrase";
    let result = derive_key_argon2(passphrase);
    assert!(result.is_ok());

    let (key, _salt) = result.unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_large_data_encryption() {
    let key = generate_key();
    let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB of data

    let (ciphertext, nonce, tag) = encrypt(CipherSuite::Aes256Gcm, &key, &plaintext).unwrap();
    let decrypted = decrypt(CipherSuite::Aes256Gcm, &key, &ciphertext, &nonce, &tag).unwrap();

    assert_eq!(decrypted.len(), plaintext.len());
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_multi_cipher_determinism() {
    // Same key and nonce would produce same ciphertext (but we use random nonces)
    // Test that each encryption produces different output (random nonce)
    let key = generate_key();
    let plaintext = b"Same plaintext, different nonce -> different ciphertext";

    let (ct1, _, _) = encrypt(CipherSuite::Aes256Gcm, &key, plaintext).unwrap();
    let (ct2, _, _) = encrypt(CipherSuite::Aes256Gcm, &key, plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

#[test]
fn test_secure_delete_nonexistent_file() {
    let path = std::path::Path::new("C:\\nonexistent_file_avgvsto_test_.tmp");
    let result = secure_delete(path, None);
    assert!(result.is_err());
}

#[test]
fn test_usb_identifier_format() {
    let temp_dir = std::env::temp_dir();
    let id = get_usb_identifier(temp_dir.to_str().unwrap());

    if let Ok(identifier) = id {
        assert!(!identifier.is_empty());
        assert_eq!(identifier.len(), 64); // SHA-256 hex is 64 chars
    }
}
