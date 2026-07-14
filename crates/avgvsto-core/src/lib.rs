mod crypto;
mod error;
mod types;
mod usb;
mod secure_delete;

pub use crypto::*;
pub use error::*;
pub use types::*;
pub use usb::*;
pub use secure_delete::*;

pub const APP_NAME: &str = "AVGVSTO";
pub const APP_VERSION: &str = "0.1.0";
pub const MAGIC: &[u8; 8] = b"AVGVSTO2";
pub const ENC_EXTENSION: &str = ".avgvsto";
pub const PBKDF2_ITERATIONS: u32 = 1_000_000;
pub const SECURE_DELETE_PASSES: u32 = 3;

pub const FORMAT_VER_1: u8 = 1;
pub const FORMAT_VER_2: u8 = 2;
pub const FORMAT_VER_3: u8 = 3;

pub const CIPHER_AES: u8 = 0x00;
pub const CIPHER_CHACHA20: u8 = 0x01;

pub const HEADER_SIZE_V1: usize = 8 + 1 + 2 + 16 + 12;
pub const TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
