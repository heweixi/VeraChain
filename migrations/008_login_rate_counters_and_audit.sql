CREATE TABLE IF NOT EXISTS login_rate_counters (
    key TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    locked_until INTEGER,
    PRIMARY KEY (key, window_start)
);
CREATE TABLE IF NOT EXISTS auth_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    username_attempted TEXT,
    session_id TEXT,
    ip_hash TEXT,
    user_agent TEXT,
    result TEXT NOT NULL,
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON auth_audit_log(ts)
