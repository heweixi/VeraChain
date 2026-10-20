CREATE TABLE IF NOT EXISTS revoked_refresh_tokens (
    jti TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    reason TEXT,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_refresh_user_id ON revoked_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_revoked_refresh_family_id ON revoked_refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_revoked_refresh_expires_at ON revoked_refresh_tokens(expires_at);
