use chrono::{TimeZone, Utc};
use parking_lot::RwLock;
use std::sync::Arc;

use super::block::{Block, KeyTransactionEntry, MetadataEntry};
use crate::catalog::CatalogRecord;
use crate::error::{DataChainError, Result};

/// 仅在内存 pending 队列中保留的身份交易协调信息。
///
/// `transaction_id` 是 SQLite 账本的 sidecar，不进入 `Block`，因此不会改变区块 JSON、
/// 签名或 Merkle 负载。
#[derive(Debug, Clone)]
struct PendingKeyTransaction {
    /// 仅持久账本管理的条目带有 sidecar ID；兼容的公开 API 添加的条目保持 `None`。
    transaction_id: Option<String>,
    entry: KeyTransactionEntry,
}

/// 一次挖矿的结果。身份交易 ID 映射仅供持久层提交状态使用，不属于区块协议。
#[derive(Debug, Clone)]
pub struct MinedBlock {
    pub block: Block,
    /// 与 `block.key_transactions` 按位置对齐的身份账本 sidecar 映射。
    ///
    /// `Some(id)` 表示对应条目来自持久身份账本；`None` 表示原有公开 API 加入的
    /// 普通密钥交易。该映射不进入区块 JSON、签名或 Merkle 负载。
    pub identity_transaction_ids: Vec<Option<String>>,
}

/// 区块链
pub struct Chain {
    blocks: RwLock<Vec<Block>>,
    difficulty: u32,
    block_size: usize,
    pending: RwLock<Vec<MetadataEntry>>,
    /// 待打包的密钥交易(backlog L1)。与元数据 pending 并列,下次挖矿并入区块。
    pending_key_tx: RwLock<Vec<PendingKeyTransaction>>,
    /// 待打包的完整语义目录记录(Subject/Revision/Artifact/Claim)。
    pending_catalog_records: RwLock<Vec<CatalogRecord>>,
}

impl Chain {
    /// 创建新的区块链
    pub fn new(difficulty: u32, block_size: usize) -> Self {
        Self {
            blocks: RwLock::new(Vec::new()),
            difficulty,
            block_size,
            pending: RwLock::new(Vec::new()),
            pending_key_tx: RwLock::new(Vec::new()),
            pending_catalog_records: RwLock::new(Vec::new()),
        }
    }

    /// 加入一条待打包密钥交易。
    ///
    /// 这是原有公开 API。该 API 不带持久身份账本 sidecar，调用方可继续使用
    /// `mine_block` 与 `rollback_mined_block` 维持原有行为。
    pub fn add_key_transaction(&self, entry: KeyTransactionEntry) {
        self.pending_key_tx.write().push(PendingKeyTransaction {
            transaction_id: None,
            entry,
        });
    }

    /// 按持久账本 ID 加入一条待打包密钥交易。
    ///
    /// handlers 与 CLI 必须使用这个显式协调接口，以便
    /// `mine_block_with_identity_transaction_ids` 将实际入块条目对应的账本 ID
    /// 交给 `Storage::commit_block`。重复 ID 不得重复入队。
    pub fn add_pending_key_transaction(
        &self,
        transaction_id: String,
        entry: KeyTransactionEntry,
    ) -> bool {
        let mut pending = self.pending_key_tx.write();
        if pending.iter().any(|transaction| {
            transaction.transaction_id.as_deref() == Some(transaction_id.as_str())
        }) {
            return false;
        }
        pending.push(PendingKeyTransaction {
            transaction_id: Some(transaction_id),
            entry,
        });
        true
    }

    /// 待打包密钥交易数量。
    pub fn get_pending_key_tx_count(&self) -> usize {
        self.pending_key_tx.read().len()
    }

    /// 从持久账本恢复待打包密钥交易，并按 transaction_id 去重保留首次接受顺序。
    pub fn load_pending_key_transactions(
        &self,
        txs: impl IntoIterator<Item = (String, KeyTransactionEntry)>,
    ) {
        let mut pending = self.pending_key_tx.write();
        pending.clear();
        for (transaction_id, entry) in txs {
            if pending.iter().all(|transaction| {
                transaction.transaction_id.as_deref() != Some(transaction_id.as_str())
            }) {
                pending.push(PendingKeyTransaction {
                    transaction_id: Some(transaction_id),
                    entry,
                });
            }
        }
    }

    /// 加载待打包密钥交易(从存储恢复)。
    ///
    /// 这是原有公开 API 的兼容 wrapper。其条目没有身份账本 sidecar，故挖矿结果中
    /// 对应位置的 `identity_transaction_ids` 为 `None`。
    pub fn load_pending_key_tx(&self, txs: Vec<KeyTransactionEntry>) {
        *self.pending_key_tx.write() = txs
            .into_iter()
            .map(|entry| PendingKeyTransaction {
                transaction_id: None,
                entry,
            })
            .collect();
    }

    /// 加入一条待打包语义目录记录。
    pub fn add_catalog_record(&self, record: CatalogRecord) {
        self.pending_catalog_records.write().push(record);
    }

    /// 待打包语义目录记录数量。
    pub fn get_pending_catalog_record_count(&self) -> usize {
        self.pending_catalog_records.read().len()
    }

    /// 从持久化存储恢复待打包语义目录记录。
    pub fn load_pending_catalog_records(&self, records: Vec<CatalogRecord>) {
        *self.pending_catalog_records.write() = records;
    }

    /// 检查一个稳定语义标识是否已在已上链或待打包目录记录中出现。
    /// 提交 Subject/Revision/Artifact/Claim 前用它保证主标识唯一，并允许同批依赖关系。
    pub fn has_catalog_record(&self, record_type: &str, primary_id: &str) -> bool {
        let committed = self.blocks.read().iter().any(|block| {
            block.catalog_records.iter().any(|record| {
                record.record_type() == record_type && record.payload.primary_id() == primary_id
            })
        });
        committed
            || self.pending_catalog_records.read().iter().any(|record| {
                record.record_type() == record_type && record.payload.primary_id() == primary_id
            })
    }

    /// 为最新区块写入 identity_snapshot_hash(backlog L1)。
    ///
    /// snapshot_hash 是派生自 key_transactions(已进 merkle_root 受保护)的当前身份集摘要,
    /// **不参与** PoW 区块哈希,故挖矿后填入不会使区块 hash 失配。仅当 index/hash 匹配
    /// 给定区块时更新,返回是否更新成功;调用方据此保证内存与持久化副本一致。
    pub fn set_latest_identity_snapshot(&self, block: &Block, snapshot_hash: &str) -> bool {
        let mut blocks = self.blocks.write();
        match blocks.last_mut() {
            Some(latest) if latest.index == block.index && latest.hash == block.hash => {
                latest.identity_snapshot_hash = snapshot_hash.to_string();
                true
            }
            _ => false,
        }
    }

    /// 初始化区块链（创建创世区块）
    pub fn init(&self) -> Block {
        let mut genesis = Block::new(0, "0".to_string(), self.difficulty);
        genesis.timestamp = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        genesis.mine();

        let mut blocks = self.blocks.write();
        blocks.push(genesis.clone());
        genesis
    }

    /// 使用身份注册创建创世区块 (Requirement 8.1)
    pub fn init_with_registry(&self, registry: serde_json::Value) -> Block {
        let mut genesis = Block::new(0, "0".to_string(), self.difficulty);
        genesis.timestamp = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        genesis.identity_registry = Some(registry);
        genesis.mine();

        let mut blocks = self.blocks.write();
        blocks.push(genesis.clone());
        genesis
    }

    /// 获取最新区块
    pub fn get_latest_block(&self) -> Option<Block> {
        let blocks = self.blocks.read();
        blocks.last().cloned()
    }

    /// 获取指定索引的区块
    pub fn get_block(&self, index: i64) -> Result<Block> {
        let blocks = self.blocks.read();
        blocks
            .get(index as usize)
            .cloned()
            .ok_or(DataChainError::BlockNotFound(index))
    }

    /// 获取区块列表
    pub fn get_blocks(&self, start: usize, limit: usize) -> Vec<Block> {
        let blocks = self.blocks.read();
        let end = (start + limit).min(blocks.len());
        if start >= blocks.len() {
            return Vec::new();
        }
        blocks[start..end].to_vec()
    }

    /// 获取所有区块
    pub fn get_all_blocks(&self) -> Vec<Block> {
        self.blocks.read().clone()
    }

    /// 获取区块数量
    pub fn get_block_count(&self) -> usize {
        self.blocks.read().len()
    }

    /// 添加元数据（加入待打包队列）
    pub fn add_metadata(&self, entry: MetadataEntry) {
        let mut pending = self.pending.write();
        pending.push(entry);
    }

    /// 获取待打包元数据数量
    pub fn get_pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// 从持久化存储恢复待打包元数据。
    pub fn load_pending(&self, entries: Vec<MetadataEntry>) {
        let mut pending = self.pending.write();
        *pending = entries;
    }

    /// 删除指定的待打包元数据。
    pub fn remove_pending_metadata(&self, data_id: &str) -> bool {
        let mut pending = self.pending.write();
        if let Some(pos) = pending.iter().position(|entry| entry.data_id == data_id) {
            pending.remove(pos);
            true
        } else {
            false
        }
    }

    /// 回滚由原有公开 `mine_block` 返回的区块。
    ///
    /// 兼容 API 创建的 key transaction 没有持久身份账本 sidecar，因此会作为普通
    /// 待打包条目恢复。
    pub fn rollback_mined_block(&self, block: &Block) -> bool {
        self.rollback_mined_block_with_sidecars(
            block,
            std::iter::repeat_with(|| None).take(block.key_transactions.len()),
        )
    }

    /// 回滚尚未完成持久化的带身份账本 sidecar 挖矿结果。
    ///
    /// 挖矿和 SQLite 写入不是同一事务；handlers 与 CLI 必须只在
    /// `Storage::commit_block` 失败时调用此显式协调接口。每条 ID 都与其原始
    /// key transaction 一同按顺序恢复。sidecar 数量与 key transaction 数量不一致时
    /// 返回 `false`，且不修改内存链或任何 pending 队列。
    pub fn rollback_mined_block_with_identity_transaction_ids(&self, mined: &MinedBlock) -> bool {
        // 先验证 sidecar 与区块密钥交易逐项对齐，避免 `zip` 静默截断后已移除
        // 链块或恢复不完整的 pending 队列。
        if mined.identity_transaction_ids.len() != mined.block.key_transactions.len() {
            return false;
        }

        self.rollback_mined_block_with_sidecars(
            &mined.block,
            mined.identity_transaction_ids.iter().cloned(),
        )
    }

    fn rollback_mined_block_with_sidecars(
        &self,
        block: &Block,
        sidecars: impl IntoIterator<Item = Option<String>>,
    ) -> bool {
        let mut blocks = self.blocks.write();
        let is_latest = blocks
            .last()
            .map(|latest| latest.index == block.index && latest.hash == block.hash)
            .unwrap_or(false);
        if !is_latest {
            return false;
        }
        blocks.pop();
        drop(blocks);

        let mut pending = self.pending.write();
        let mut restored = block.metadata_list.clone();
        restored.append(&mut *pending);
        *pending = restored;
        drop(pending);

        let mut pending_key_tx = self.pending_key_tx.write();
        let mut restored_tx = block
            .key_transactions
            .iter()
            .cloned()
            .zip(sidecars)
            .map(|(entry, transaction_id)| PendingKeyTransaction {
                transaction_id,
                entry,
            })
            .collect::<Vec<_>>();
        restored_tx.append(&mut *pending_key_tx);
        *pending_key_tx = restored_tx;
        drop(pending_key_tx);

        let mut pending_catalog = self.pending_catalog_records.write();
        let mut restored_catalog = block.catalog_records.clone();
        restored_catalog.append(&mut *pending_catalog);
        *pending_catalog = restored_catalog;
        true
    }

    /// 挖掘新区块。
    ///
    /// 这是原有公开 API。它只返回不可变的 `Block`，不会暴露身份账本 sidecar。
    pub fn mine_block(&self) -> Result<Block> {
        self.mine_block_with_identity_transaction_ids()
            .map(|mined| mined.block)
    }

    /// 挖掘新区块，并返回身份账本协调所需的 sidecar。
    ///
    /// handlers 与 CLI 必须使用此接口，并仅将返回的
    /// `identity_transaction_ids` 传给 `Storage::commit_block`。ID 不写入区块，
    /// 因此不会改变既有 JSON、签名或 Merkle 负载。
    pub fn mine_block_with_identity_transaction_ids(&self) -> Result<MinedBlock> {
        let blocks = self.blocks.read();
        if blocks.is_empty() {
            return Err(DataChainError::ChainNotInitialized);
        }

        let mut pending = self.pending.write();
        let mut pending_key_tx = self.pending_key_tx.write();
        let mut pending_catalog = self.pending_catalog_records.write();
        if pending.is_empty() && pending_key_tx.is_empty() && pending_catalog.is_empty() {
            return Err(DataChainError::AggregationFailed(
                "no pending metadata, key transactions, or catalog records".to_string(),
            ));
        }

        let latest = blocks.last().unwrap();
        let mut new_block = Block::new(latest.index + 1, latest.hash.clone(), self.difficulty);

        // 添加待打包的元数据
        let count = self.block_size.min(pending.len());
        for entry in pending.drain(..count) {
            new_block.add_metadata(entry);
        }

        // sidecar 仅留在协调结果中，绝不进入区块序列化或 Merkle 负载。
        let pending_key_transactions = pending_key_tx.drain(..).collect::<Vec<_>>();
        let identity_transaction_ids = pending_key_transactions
            .iter()
            .map(|transaction| transaction.transaction_id.clone())
            .collect::<Vec<_>>();
        new_block.key_transactions = pending_key_transactions
            .into_iter()
            .map(|transaction| transaction.entry)
            .collect();
        // 并入完整语义目录记录;其 leaf_hash 覆盖完整 Subject/Revision/Artifact/Claim 内容。
        new_block.catalog_records = pending_catalog.drain(..).collect();

        drop(pending_catalog);
        drop(pending_key_tx);
        drop(pending);
        drop(blocks);

        // 挖矿
        new_block.mine();

        // 添加到链
        let mut blocks = self.blocks.write();
        blocks.push(new_block.clone());

        Ok(MinedBlock {
            block: new_block,
            identity_transaction_ids,
        })
    }

    /// 添加区块（用于同步）
    pub fn add_block(&self, block: Block) -> Result<()> {
        let mut blocks = self.blocks.write();

        if blocks.is_empty() {
            return Err(DataChainError::ChainNotInitialized);
        }

        let latest = blocks.last().unwrap();

        // 验证区块
        if block.index != latest.index + 1 {
            return Err(DataChainError::InvalidBlock("invalid index".to_string()));
        }
        if block.previous_hash != latest.hash {
            return Err(DataChainError::InvalidBlock(
                "invalid previous hash".to_string(),
            ));
        }
        if !block.is_valid() {
            return Err(DataChainError::InvalidBlock(
                "invalid proof of work".to_string(),
            ));
        }

        blocks.push(block);
        Ok(())
    }

    /// 验证整条链的完整性
    pub fn validate_chain(&self) -> bool {
        let blocks = self.blocks.read();

        for i in 1..blocks.len() {
            let current = &blocks[i];
            let previous = &blocks[i - 1];

            // 验证哈希
            if current.hash != current.calculate_hash() {
                return false;
            }

            // 验证链接
            if current.previous_hash != previous.hash {
                return false;
            }

            // 验证工作量证明
            if !current.is_valid() {
                return false;
            }
        }

        true
    }

    /// 获取链信息
    pub fn get_chain_info(&self) -> ChainInfo {
        let blocks = self.blocks.read();
        let pending = self.pending.read();

        ChainInfo {
            block_count: blocks.len(),
            difficulty: self.difficulty,
            block_size: self.block_size,
            pending_count: pending.len(),
            latest_block: blocks.last().map(|b| LatestBlockInfo {
                index: b.index,
                hash: b.hash.clone(),
                timestamp: b.timestamp,
            }),
        }
    }

    /// 验证待加载区块，不通过时不替换当前内存链。
    pub fn validate_loaded_blocks(&self, blocks: &[Block]) -> Result<()> {
        if blocks.is_empty() {
            return Err(DataChainError::InvalidChain);
        }

        let genesis = &blocks[0];
        if genesis.index != 0 || genesis.previous_hash != "0" {
            return Err(DataChainError::InvalidBlock(
                "invalid genesis block".to_string(),
            ));
        }

        for (position, block) in blocks.iter().enumerate() {
            if block.index != position as i64 {
                return Err(DataChainError::InvalidBlock(format!(
                    "invalid block index at position {}",
                    position
                )));
            }
            if block.hash != block.calculate_hash() || !block.is_valid() {
                return Err(DataChainError::InvalidBlock(format!(
                    "invalid block hash or proof of work at index {}",
                    block.index
                )));
            }
            if block.merkle_root != block.calculate_merkle_root() {
                return Err(DataChainError::InvalidBlock(format!(
                    "invalid merkle root at index {}",
                    block.index
                )));
            }
            if position > 0 && block.previous_hash != blocks[position - 1].hash {
                return Err(DataChainError::InvalidBlock(format!(
                    "invalid previous hash at index {}",
                    block.index
                )));
            }
        }

        Ok(())
    }

    /// 用更长且完整校验通过的候选链替换本地链。
    /// 同长度分叉不自动覆盖，避免在没有共识规则时发生静默分叉选择。
    pub fn replace_chain_if_longer(&self, candidate: Vec<Block>) -> Result<bool> {
        self.validate_loaded_blocks(&candidate)?;
        let mut blocks = self.blocks.write();
        if candidate.len() <= blocks.len() {
            return Ok(false);
        }
        *blocks = candidate;
        Ok(true)
    }

    /// 加载区块（从存储恢复）。调用方应先调用 validate_loaded_blocks。
    pub fn load_blocks(&self, blocks: Vec<Block>) {
        let mut chain_blocks = self.blocks.write();
        *chain_blocks = blocks;
    }
}

/// 链信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainInfo {
    pub block_count: usize,
    pub difficulty: u32,
    pub block_size: usize,
    pub pending_count: usize,
    pub latest_block: Option<LatestBlockInfo>,
}

/// 最新区块信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct LatestBlockInfo {
    pub index: i64,
    pub hash: String,
    pub timestamp: chrono::DateTime<Utc>,
}

/// 创建共享的 Chain 实例
pub fn create_chain(difficulty: u32, block_size: usize) -> Arc<Chain> {
    Arc::new(Chain::new(difficulty, block_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_init() {
        let chain = Chain::new(2, 100);
        let genesis = chain.init();
        assert_eq!(genesis.index, 0);
        assert_eq!(chain.get_block_count(), 1);
    }

    #[test]
    fn test_chain_validation() {
        let chain = Chain::new(2, 100);
        chain.init();
        assert!(chain.validate_chain());
    }

    #[test]
    fn test_loaded_blocks_validate_merkle_payload() {
        let chain = Chain::new(1, 100);
        let mut genesis = chain.init();
        genesis.metadata_list.push(MetadataEntry {
            data_id: "tampered".to_string(),
            data_size: 1,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            owner: "tester".to_string(),
            hashes: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            parent_id: None,
            tags: Vec::new(),
        });
        assert!(chain.validate_loaded_blocks(&[genesis]).is_err());
    }

    fn pending_identity_entry() -> KeyTransactionEntry {
        KeyTransactionEntry {
            tx_type: "register".to_string(),
            target_key: "key-a".to_string(),
            role: "node".to_string(),
            label: "pending".to_string(),
            signed_by: "key-a".to_string(),
            signature: "signature".to_string(),
            timestamp: 10,
            reason: String::new(),
        }
    }

    #[test]
    fn legacy_key_transaction_and_mining_apis_remain_usable() {
        let chain = Chain::new(1, 100);
        chain.init();
        let entry = pending_identity_entry();

        chain.add_key_transaction(entry.clone());
        let block = chain.mine_block().unwrap();

        assert_eq!(block.key_transactions, vec![entry]);
        assert!(chain.rollback_mined_block(&block));
        assert_eq!(chain.get_block_count(), 1);
        assert_eq!(chain.get_pending_key_tx_count(), 1);
    }

    #[test]
    fn legacy_load_pending_key_tx_wrapper_restores_entries_without_identity_sidecars() {
        let chain = Chain::new(1, 100);
        chain.init();
        let entry = pending_identity_entry();

        chain.load_pending_key_tx(vec![entry.clone()]);
        let mined = chain.mine_block_with_identity_transaction_ids().unwrap();

        assert_eq!(mined.block.key_transactions, vec![entry]);
        assert_eq!(mined.identity_transaction_ids, vec![None]);
    }

    #[test]
    fn sidecar_mining_keeps_an_aligned_mapping_for_mixed_key_transactions_and_rolls_back_together()
    {
        let chain = Chain::new(1, 100);
        chain.init();
        let entry = pending_identity_entry();
        let mut legacy_entry = pending_identity_entry();
        legacy_entry.target_key = "key-legacy".to_string();
        legacy_entry.signed_by = "key-legacy".to_string();

        chain.add_key_transaction(legacy_entry.clone());
        assert!(chain.add_pending_key_transaction("tx-a".to_string(), entry.clone()));
        let mined = chain.mine_block_with_identity_transaction_ids().unwrap();
        assert_eq!(
            mined.identity_transaction_ids,
            vec![None, Some("tx-a".to_string())]
        );
        assert_eq!(mined.block.key_transactions, vec![legacy_entry, entry]);

        assert!(chain.rollback_mined_block_with_identity_transaction_ids(&mined));
        assert_eq!(chain.get_block_count(), 1);
        assert_eq!(chain.get_pending_key_tx_count(), 2);

        let remine = chain.mine_block_with_identity_transaction_ids().unwrap();
        assert_eq!(
            remine.identity_transaction_ids,
            vec![None, Some("tx-a".to_string())]
        );
        assert_eq!(remine.block.key_transactions.len(), 2);
    }

    #[test]
    fn sidecar_rollback_rejects_misaligned_sidecars_without_changing_chain_or_pending_transactions()
    {
        let chain = Chain::new(1, 100);
        chain.init();
        let entry = pending_identity_entry();
        assert!(chain.add_pending_key_transaction("tx-a".to_string(), entry));
        let mut mined = chain.mine_block_with_identity_transaction_ids().unwrap();

        let mut later_entry = pending_identity_entry();
        later_entry.target_key = "key-later".to_string();
        later_entry.signed_by = "key-later".to_string();
        assert!(chain.add_pending_key_transaction("tx-later".to_string(), later_entry.clone()));
        mined.identity_transaction_ids.clear();

        assert!(!chain.rollback_mined_block_with_identity_transaction_ids(&mined));
        assert_eq!(chain.get_block_count(), 2);
        assert_eq!(chain.get_pending_key_tx_count(), 1);

        let next_mined = chain.mine_block_with_identity_transaction_ids().unwrap();
        assert_eq!(next_mined.block.key_transactions, vec![later_entry]);
        assert_eq!(
            next_mined.identity_transaction_ids,
            vec![Some("tx-later".to_string())]
        );
    }
}
