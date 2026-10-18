CREATE TABLE IF NOT EXISTS anchor_outbox (
    anchor_id TEXT PRIMARY KEY NOT NULL,
    target_chain_id TEXT NOT NULL,
    data_id TEXT NOT NULL,
    signed TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    receipt TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_anchor_outbox_status ON anchor_outbox(status);
CREATE INDEX IF NOT EXISTS idx_anchor_outbox_data_id ON anchor_outbox(data_id);
