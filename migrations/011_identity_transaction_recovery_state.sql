-- `transaction_id` 不在不可变区块协议中。010 创建账本表后、011 升级前已存在的 pending 行
-- 无法从区块 JSON 证明未被打包，因此升级后默认标记为不可恢复，启动时必须 fail-closed。
ALTER TABLE identity_transactions
    ADD COLUMN recovery_state TEXT NOT NULL DEFAULT 'legacy_unverified'
    CHECK (recovery_state IN ('legacy_unverified', 'verified'));
CREATE INDEX IF NOT EXISTS idx_identity_transactions_recovery_state
    ON identity_transactions(status, recovery_state, accepted_at, transaction_id);
