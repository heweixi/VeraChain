CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    block_index INTEGER UNIQUE NOT NULL,
    timestamp INTEGER NOT NULL,
    previous_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    nonce INTEGER NOT NULL,
    difficulty INTEGER NOT NULL,
    hash TEXT UNIQUE NOT NULL,
    data TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    public_key TEXT,
    created_at DATETIME NOT NULL,
    last_login DATETIME,
    is_active INTEGER DEFAULT 1,
    metadata TEXT
);
CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id TEXT UNIQUE NOT NULL,
    timestamp DATETIME NOT NULL,
    file_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    author TEXT NOT NULL,
    message TEXT,
    parent_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);
CREATE INDEX IF NOT EXISTS idx_blocks_index ON blocks(block_index);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_versions_file_path ON versions(file_path);
