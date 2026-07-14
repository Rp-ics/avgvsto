use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("invalid magic bytes")]
    InvalidMagic,

    #[error("unsupported format version: {0}")]
    UnsupportedFormat(u8),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("USB key not found")]
    UsbKeyNotFound,

    #[error("max attempts exceeded")]
    MaxAttemptsExceeded,

    #[error("invalid file format")]
    InvalidFileFormat,

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("secure delete failed: {0}")]
    SecureDelete(String),
}

pub type CoreResult<T> = Result<T, CoreError>;
