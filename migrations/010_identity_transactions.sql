CREATE TABLE IF NOT EXISTS identity_transactions (
    transaction_id TEXT PRIMARY KEY NOT NULL,
    submitter_user_id TEXT NOT NULL,
    idempotency_key TEXT,
    request_fingerprint TEXT NOT NULL,
    entry TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'committed')),
    committed_block_index INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_transactions_submitter_idempotency
    ON identity_transactions(submitter_user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_identity_transactions_pending_order
    ON identity_transactions(status, accepted_at, transaction_id);
