use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileHeader {
    pub magic: [u8; 8],
    pub version: u8,
    pub flags: u8,
    pub cipher_id: u8,
    pub max_attempts: u16,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub data: Vec<u8>,
    pub cipher: Option<CipherSuite>,
    pub passphrase: Option<String>,
    pub usb_key_path: Option<String>,
    pub max_attempts: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub encrypted_data: Vec<u8>,
    pub file_id: Uuid,
    pub cipher: CipherSuite,
    pub format_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub encrypted_data: Vec<u8>,
    pub passphrase: Option<String>,
    pub usb_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecryptResponse {
    pub data: Vec<u8>,
    pub cipher: CipherSuite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub encrypted_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyResponse {
    pub valid: bool,
    pub format_version: u8,
    pub cipher: Option<CipherSuite>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum CipherSuite {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl CipherSuite {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            super::CIPHER_AES => Some(Self::Aes256Gcm),
            super::CIPHER_CHACHA20 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::Aes256Gcm => super::CIPHER_AES,
            Self::ChaCha20Poly1305 => super::CIPHER_CHACHA20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbKeyInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_identifier: String,
    pub public_hash: String,
    pub mount_path: String,
    pub bound_at: chrono::DateTime<chrono::Utc>,
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for UsbKeyInfo {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            key_identifier: row.try_get("key_identifier")?,
            public_hash: row.try_get("public_hash")?,
            mount_path: row.try_get("mount_path")?,
            bound_at: row.try_get("bound_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub files_encrypted: u64,
    pub files_decrypted: u64,
    pub bytes_encrypted: u64,
    pub bytes_decrypted: u64,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}
