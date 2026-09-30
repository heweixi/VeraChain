CREATE TABLE IF NOT EXISTS pending_metadata (
    data_id TEXT PRIMARY KEY NOT NULL,
    data TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS aggregations (
    summary_id TEXT PRIMARY KEY NOT NULL,
    created_at DATETIME NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aggregations_created_at ON aggregations(created_at);
