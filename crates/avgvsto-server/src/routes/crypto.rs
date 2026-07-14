use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

use avgvsto_core::{
    decrypt, encrypt, CipherSuite, DecryptResponse, VerifyResponse,
};

use avgvsto_audit::{AuditAction, CreateAuditEvent};

use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::middleware::auth::AuthenticatedUser;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .route("/verify", post(verify_handler))
        .route("/encrypt-file", post(encrypt_file_handler))
        .route("/decrypt-file", post(decrypt_file_handler))
        .route("/keys/bind-usb", post(bind_usb_key))
        .route("/keys", get(list_keys))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EncryptBody {
    pub data: String,
    pub cipher: Option<String>,
    pub passphrase: Option<String>,
    pub usb_key_path: Option<String>,
    pub use_duress: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EncryptResponseBody {
    pub encrypted_data: String,
    pub file_id: Uuid,
    pub cipher: String,
    pub format_version: u8,
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.decode(data)
}

async fn enforce_usb(
    state: &AppState,
    user_id: Uuid,
    usb_key_path: Option<&str>,
) -> Result<(), (StatusCode, Json<crate::error::ApiError>)> {
    let bound_keys: Vec<(String,)> = sqlx::query_as(
        "SELECT key_identifier FROM keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| crate::error::internal("Failed to check USB keys"))?;

    if bound_keys.is_empty() {
        return Err(crate::error::forbidden(
            "USB key required: no keys bound to this account",
            "USB_KEY_REQUIRED",
        ));
    }

    if let Some(path) = usb_key_path {
        let identifier = avgvsto_core::get_usb_identifier(path)
            .map_err(|_| crate::error::bad_request("USB device not found at specified path", "USB_NOT_FOUND"))?;

        let matched = bound_keys.iter().any(|(kid,)| *kid == identifier);
        if !matched {
            return Err(crate::error::forbidden(
                "USB key mismatch: device not registered to this account",
                "USB_MISMATCH",
            ));
        }
    }

    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/v1/encrypt",
    tag = "crypto",
    request_body = EncryptBody,
    responses(
        (status = 200, description = "Data encrypted successfully", body = EncryptResponseBody),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 403, description = "USB key required", body = ApiError),
    )
)]
async fn encrypt_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<EncryptBody>,
) -> ApiResult<impl IntoResponse> {
    enforce_usb(&state, user.user_id, body.usb_key_path.as_deref()).await?;

    let cipher = match body.cipher.as_deref() {
        Some("chacha20-poly1305") => CipherSuite::ChaCha20Poly1305,
        _ => CipherSuite::Aes256Gcm,
    };

    let passphrase = body
        .passphrase
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let salt = avgvsto_core::generate_salt();
    let key = avgvsto_core::derive_key_pbkdf2(&passphrase, &salt);

    let plaintext = body.data.as_bytes();

    let (ciphertext, nonce, tag) = if body.use_duress.unwrap_or(false) {
        avgvsto_core::duress_encrypt(cipher, &key, plaintext)
    } else {
        encrypt(cipher, &key, plaintext)
    }
    .map_err(|_| crate::error::internal("Encryption failed"))?;

    state
        .audit_store
        .create_event(CreateAuditEvent {
            user_id: Some(user.user_id),
            action: AuditAction::FileEncrypted,
            resource: Some("data".to_string()),
            details: serde_json::json!({
                "cipher": format!("{:?}", cipher),
                "size": plaintext.len(),
            }),
            ip_address: None,
            user_agent: None,
        })
        .await
        .ok();

    let mut combined = Vec::with_capacity(8 + 1 + 1 + 1 + 2 + 16 + 12 + 16 + 4 + ciphertext.len());
    combined.extend_from_slice(avgvsto_core::MAGIC);
    combined.push(avgvsto_core::FORMAT_VER_3);
    combined.push(0);
    combined.push(cipher.to_byte());
    combined.extend_from_slice(&500u16.to_be_bytes());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    combined.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    combined.extend_from_slice(&ciphertext);

    Ok(Json(serde_json::json!(EncryptResponseBody {
        encrypted_data: base64_encode(&combined),
        file_id: Uuid::new_v4(),
        cipher: format!("{:?}", cipher),
        format_version: avgvsto_core::FORMAT_VER_3,
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/decrypt",
    tag = "crypto",
    request_body = DecryptBody,
    responses(
        (status = 200, description = "Data decrypted successfully", body = DecryptResponse),
        (status = 400, description = "Bad request", body = ApiError),
        (status = 401, description = "Decryption failed", body = ApiError),
    )
)]
async fn decrypt_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<DecryptBody>,
) -> ApiResult<impl IntoResponse> {
    let data = base64_decode(&body.encrypted_data)
        .map_err(|_| crate::error::bad_request("Invalid base64 encoding", "INVALID_ENCODING"))?;

    if data.len() < avgvsto_core::HEADER_SIZE_V1 {
        return Err(crate::error::bad_request("Data too short", "INVALID_DATA"));
    }

    let magic = &data[..8];
    if magic != avgvsto_core::MAGIC {
        return Err(crate::error::bad_request("Invalid magic bytes", "INVALID_MAGIC"));
    }

    let version = data[8];
    let _flags = data[9];
    let cipher_id = data[10];
    let _max_attempts = u16::from_be_bytes([data[11], data[12]]);
    let salt: [u8; 16] = data[13..29].try_into().unwrap();
    let nonce: [u8; 12] = data[29..41].try_into().unwrap();
    let tag: [u8; 16] = data[41..57].try_into().unwrap();
    let ct_len = u32::from_be_bytes([data[57], data[58], data[59], data[60]]) as usize;
    let ciphertext = &data[61..61 + ct_len];

    let cipher = CipherSuite::from_byte(cipher_id)
        .ok_or_else(|| crate::error::bad_request("Unknown cipher", "UNKNOWN_CIPHER"))?;

    let passphrase = body
        .passphrase
        .ok_or_else(|| crate::error::bad_request("Passphrase required", "PASSPHRASE_REQUIRED"))?;

    let key = avgvsto_core::derive_key_pbkdf2(&passphrase, &salt);

    let plaintext = decrypt(cipher, &key, ciphertext, &nonce, &tag).map_err(|_| {
        crate::error::unauthorized(
            "Decryption failed: invalid passphrase or corrupted data",
            "DECRYPTION_FAILED",
        )
    })?;

    state
        .audit_store
        .create_event(CreateAuditEvent {
            user_id: Some(user.user_id),
            action: AuditAction::FileDecrypted,
            resource: None,
            details: serde_json::json!({
                "cipher": format!("{:?}", cipher),
                "format_version": version,
            }),
            ip_address: None,
            user_agent: None,
        })
        .await
        .ok();

    Ok(Json(serde_json::json!(DecryptResponse {
        data: plaintext,
        cipher,
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecryptBody {
    pub encrypted_data: String,
    pub passphrase: Option<String>,
    pub usb_key_path: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyBody {
    pub encrypted_data: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/verify",
    tag = "crypto",
    request_body = VerifyBody,
    responses(
        (status = 200, description = "Format verified", body = VerifyResponse),
        (status = 400, description = "Bad request", body = ApiError),
    )
)]
async fn verify_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<VerifyBody>,
) -> ApiResult<impl IntoResponse> {
    let data = base64_decode(&body.encrypted_data)
        .map_err(|_| crate::error::bad_request("Invalid base64 encoding", "INVALID_ENCODING"))?;

    let valid = data.len() >= avgvsto_core::HEADER_SIZE_V1 && &data[..8] == avgvsto_core::MAGIC;

    let version = if valid { data[8] } else { 0 };
    let cipher = if valid {
        CipherSuite::from_byte(data[10])
    } else {
        None
    };

    state
        .audit_store
        .create_event(CreateAuditEvent {
            user_id: Some(user.user_id),
            action: AuditAction::FileVerified,
            resource: None,
            details: serde_json::json!({
                "valid": valid,
                "format_version": version,
            }),
            ip_address: None,
            user_agent: None,
        })
        .await
        .ok();

    Ok(Json(serde_json::json!(VerifyResponse {
        valid,
        format_version: version,
        cipher,
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/encrypt-file",
    tag = "crypto",
    request_body(content = String, description = "File upload (multipart/form-data)"),
    responses(
        (status = 200, description = "File encrypted successfully", body = EncryptResponseBody),
        (status = 400, description = "Bad request", body = ApiError),
    )
)]
async fn encrypt_file_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let mut file_data = Vec::new();
    let mut passphrase: Option<String> = None;
    let mut cipher_name: Option<String> = None;
    let mut usb_key_path: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                file_data = field.bytes().await.map_err(|_| {
                    crate::error::bad_request("Failed to read file data", "FILE_READ_ERROR")
                })?.to_vec();
            }
            "passphrase" => {
                passphrase = Some(field.text().await.unwrap_or_default());
            }
            "cipher" => {
                cipher_name = Some(field.text().await.unwrap_or_default());
            }
            "usb_key_path" => {
                usb_key_path = Some(field.text().await.unwrap_or_default());
            }
            _ => {}
        }
    }

    if file_data.is_empty() {
        return Err(crate::error::bad_request("No file uploaded", "FILE_REQUIRED"));
    }

    enforce_usb(&state, user.user_id, usb_key_path.as_deref()).await?;

    let cipher = match cipher_name.as_deref() {
        Some("chacha20-poly1305") => CipherSuite::ChaCha20Poly1305,
        _ => CipherSuite::Aes256Gcm,
    };

    let passphrase = passphrase.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let salt = avgvsto_core::generate_salt();
    let key = avgvsto_core::derive_key_pbkdf2(&passphrase, &salt);

    let (ciphertext, nonce, tag) = encrypt(cipher, &key, &file_data)
        .map_err(|_| crate::error::internal("Encryption failed"))?;

    state
        .audit_store
        .create_event(CreateAuditEvent {
            user_id: Some(user.user_id),
            action: AuditAction::FileEncrypted,
            resource: Some("file-upload".to_string()),
            details: serde_json::json!({
                "cipher": format!("{:?}", cipher),
                "size": file_data.len(),
            }),
            ip_address: None,
            user_agent: None,
        })
        .await
        .ok();

    let mut combined = Vec::with_capacity(8 + 1 + 1 + 1 + 2 + 16 + 12 + 16 + 4 + ciphertext.len());
    combined.extend_from_slice(avgvsto_core::MAGIC);
    combined.push(avgvsto_core::FORMAT_VER_3);
    combined.push(0);
    combined.push(cipher.to_byte());
    combined.extend_from_slice(&500u16.to_be_bytes());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    combined.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    combined.extend_from_slice(&ciphertext);

    Ok(Json(serde_json::json!(EncryptResponseBody {
        encrypted_data: base64_encode(&combined),
        file_id: Uuid::new_v4(),
        cipher: format!("{:?}", cipher),
        format_version: avgvsto_core::FORMAT_VER_3,
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/decrypt-file",
    tag = "crypto",
    request_body(content = String, description = "Encrypted file upload (multipart/form-data)"),
    responses(
        (status = 200, description = "File decrypted successfully"),
        (status = 400, description = "Bad request", body = ApiError),
    )
)]
async fn decrypt_file_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let mut encrypted_data = Vec::new();
    let mut passphrase: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                let bytes = field.bytes().await.map_err(|_| {
                    crate::error::bad_request("Failed to read file data", "FILE_READ_ERROR")
                })?;
                encrypted_data = base64_decode(std::str::from_utf8(&bytes).map_err(|_| {
                    crate::error::bad_request("Invalid UTF-8 in file", "INVALID_ENCODING")
                })?)
                .map_err(|_| crate::error::bad_request("Invalid base64 in file", "INVALID_ENCODING"))?;
            }
            "passphrase" => {
                passphrase = Some(field.text().await.unwrap_or_default());
            }
            _ => {}
        }
    }

    if encrypted_data.len() < avgvsto_core::HEADER_SIZE_V1 {
        return Err(crate::error::bad_request("Invalid encrypted file", "INVALID_DATA"));
    }

    if &encrypted_data[..8] != avgvsto_core::MAGIC {
        return Err(crate::error::bad_request("Invalid magic bytes", "INVALID_MAGIC"));
    }

    let version = encrypted_data[8];
    let cipher_id = encrypted_data[10];
    let salt: [u8; 16] = encrypted_data[13..29].try_into().unwrap();
    let nonce: [u8; 12] = encrypted_data[29..41].try_into().unwrap();
    let tag: [u8; 16] = encrypted_data[41..57].try_into().unwrap();
    let ct_len = u32::from_be_bytes([
        encrypted_data[57],
        encrypted_data[58],
        encrypted_data[59],
        encrypted_data[60],
    ]) as usize;
    let ciphertext = &encrypted_data[61..61 + ct_len];

    let cipher = CipherSuite::from_byte(cipher_id)
        .ok_or_else(|| crate::error::bad_request("Unknown cipher", "UNKNOWN_CIPHER"))?;

    let passphrase = passphrase
        .ok_or_else(|| crate::error::bad_request("Passphrase required", "PASSPHRASE_REQUIRED"))?;

    let key = avgvsto_core::derive_key_pbkdf2(&passphrase, &salt);
    let plaintext = decrypt(cipher, &key, ciphertext, &nonce, &tag).map_err(|_| {
        crate::error::unauthorized("Decryption failed", "DECRYPTION_FAILED")
    })?;

    state
        .audit_store
        .create_event(CreateAuditEvent {
            user_id: Some(user.user_id),
            action: AuditAction::FileDecrypted,
            resource: Some("file-upload".to_string()),
            details: serde_json::json!({
                "cipher": format!("{:?}", cipher),
                "format_version": version,
            }),
            ip_address: None,
            user_agent: None,
        })
        .await
        .ok();

    Ok(Json(serde_json::json!(DecryptResponse {
        data: plaintext,
        cipher,
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BindUsbBody {
    pub usb_path: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/keys/bind-usb",
    tag = "crypto",
    request_body = BindUsbBody,
    responses(
        (status = 200, description = "USB key bound"),
        (status = 400, description = "USB device not found", body = ApiError),
    )
)]
async fn bind_usb_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<BindUsbBody>,
) -> ApiResult<impl IntoResponse> {
    let identifier = avgvsto_core::get_usb_identifier(&body.usb_path)
        .map_err(|_| crate::error::bad_request("USB device not found", "USB_NOT_FOUND"))?;

    sqlx::query(
        r#"
        INSERT INTO keys (user_id, key_identifier, public_hash, mount_path)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, key_identifier) DO NOTHING
        "#,
    )
    .bind(user.user_id)
    .bind(&identifier)
    .bind(&identifier)
    .bind(&body.usb_path)
    .execute(&state.pool)
    .await
    .map_err(|_| crate::error::internal("Failed to bind USB key"))?;

    state
        .audit_store
        .create_event(CreateAuditEvent {
            user_id: Some(user.user_id),
            action: AuditAction::KeyBound,
            resource: Some(format!("usb/{}", body.usb_path)),
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
        })
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "status": "bound",
        "identifier": identifier,
    })))
}

#[utoipa::path(
    get,
    path = "/api/v1/keys",
    tag = "crypto",
    responses(
        (status = 200, description = "List of bound keys"),
    )
)]
async fn list_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> ApiResult<impl IntoResponse> {
    let keys = sqlx::query_as::<_, avgvsto_core::UsbKeyInfo>(
        r#"
        SELECT id, user_id, key_identifier, public_hash, mount_path, bound_at
        FROM keys
        WHERE user_id = $1
        ORDER BY bound_at DESC
        "#,
    )
    .bind(user.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| crate::error::internal("Failed to list keys"))?;

    Ok(Json(serde_json::json!(keys)))
}
