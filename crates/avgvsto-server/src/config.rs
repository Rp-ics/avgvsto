use figment::{providers::{Env, Format, Toml}, Figment};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub crypto: CryptoConfig,
    pub logging: LoggingConfig,
    pub rate_limiting: RateLimitingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub allowed_origins: Vec<String>,
    pub max_body_size: usize,
    pub request_timeout_secs: u64,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub access_token_expiry_secs: i64,
    pub refresh_token_expiry_secs: i64,
    pub bcrypt_cost: u32,
    pub max_login_attempts: usize,
    pub login_window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub default_cipher: String,
    pub pbkdf2_iterations: u32,
    pub secure_delete_passes: u32,
    pub temp_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub directory: PathBuf,
    pub max_files: u32,
    pub max_file_size_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8443,
                workers: 4,
                allowed_origins: vec!["http://localhost:3000".to_string()],
                max_body_size: 100 * 1024 * 1024,
                request_timeout_secs: 120,
                tls: TlsConfig {
                    enabled: false,
                    cert_path: String::new(),
                    key_path: String::new(),
                },
            },
            database: DatabaseConfig {
                url: "postgresql://avgvsto:avgvsto@localhost:5432/avgvsto".to_string(),
                max_connections: 20,
                min_connections: 4,
                connect_timeout_secs: 30,
                idle_timeout_secs: 300,
            },
            auth: AuthConfig {
                jwt_secret: "CHANGE-ME-TO-A-SECURE-RANDOM-KEY-AT-LEAST-32-CHARS".to_string(),
                access_token_expiry_secs: 900,
                refresh_token_expiry_secs: 604800,
                bcrypt_cost: 12,
                max_login_attempts: 5,
                login_window_secs: 300,
            },
            crypto: CryptoConfig {
                default_cipher: "aes-256-gcm".to_string(),
                pbkdf2_iterations: 1_000_000,
                secure_delete_passes: 3,
                temp_dir: None,
            },
            rate_limiting: RateLimitingConfig {
                enabled: true,
                requests_per_minute: 60,
                burst_size: 10,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                directory: PathBuf::from("/var/log/avgvsto"),
                max_files: 30,
                max_file_size_mb: 100,
            },
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, figment::Error> {
        let config_dir = std::env::var("AVGVSTO_CONFIG_DIR")
            .unwrap_or_else(|_| "config".to_string());

        Figment::new()
            .merge(Toml::file(format!("{}/default.toml", config_dir)))
            .merge(Toml::file(format!("{}/{}.toml", config_dir, "development")))
            .merge(Toml::file(format!("{}/local.toml", config_dir)))
            .merge(Env::prefixed("AVGVSTO_").split("__"))
            .extract()
    }
}
