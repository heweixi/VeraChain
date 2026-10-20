CREATE TABLE IF NOT EXISTS metadata (
    data_id TEXT PRIMARY KEY NOT NULL,
    owner TEXT NOT NULL,
    data_size INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metadata_owner ON metadata(owner);
CREATE INDEX IF NOT EXISTS idx_metadata_created_at ON metadata(created_at);
CREATE INDEX IF NOT EXISTS idx_metadata_block_index ON metadata(block_index);
