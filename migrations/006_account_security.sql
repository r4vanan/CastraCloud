-- Local-account MFA and password reset state.

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_encrypted BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_secret_encrypted BYTEA;

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash     BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash    BYTEA PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens (user_id, expires_at);
