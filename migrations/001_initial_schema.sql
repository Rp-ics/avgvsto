-- AVGVSTO Server — Initial Database Schema
-- PostgreSQL migration

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(128) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    role        VARCHAR(32) NOT NULL DEFAULT 'user',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(128) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);

-- Encrypted files metadata
CREATE TABLE IF NOT EXISTS encrypted_files (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename VARCHAR(512) NOT NULL,
    encrypted_path    TEXT NOT NULL,
    cipher            VARCHAR(32) NOT NULL DEFAULT 'aes-256-gcm',
    file_size         BIGINT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_encrypted_files_user ON encrypted_files(user_id);
CREATE INDEX IF NOT EXISTS idx_encrypted_files_created ON encrypted_files(created_at DESC);

-- Bound USB keys
CREATE TABLE IF NOT EXISTS keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_identifier  VARCHAR(256) NOT NULL,
    public_hash     VARCHAR(64) NOT NULL,
    mount_path      TEXT NOT NULL DEFAULT '',
    bound_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, key_identifier)
);

CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(64) NOT NULL,
    resource    VARCHAR(256),
    details     JSONB DEFAULT '{}'::jsonb,
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

-- Stats counter table
CREATE TABLE IF NOT EXISTS stats (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    files_encrypted   BIGINT NOT NULL DEFAULT 0,
    files_decrypted   BIGINT NOT NULL DEFAULT 0,
    bytes_encrypted   BIGINT NOT NULL DEFAULT 0,
    bytes_decrypted   BIGINT NOT NULL DEFAULT 0,
    last_activity     TIMESTAMPTZ,
    UNIQUE(user_id)
);
