use chrono::{TimeZone, Utc};
use parking_lot::RwLock;
use std::sync::Arc;

use super::block::{Block, KeyTransactionEntry, MetadataEntry};
use crate::catalog::CatalogRecord;
use crate::error::{DataChainError, Result};

/// 区块链
pub struct Chain {
    blocks: RwLock<Vec<Block>>,
    difficulty: u32,
    block_size: usize,
    pending: RwLock<Vec<MetadataEntry>>,
    /// 待打包的密钥交易(backlog L1)。与元数据 pending 并列,下次挖矿并入区块。
    pending_key_tx: RwLock<Vec<KeyTransactionEntry>>,
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
    pub fn add_key_transaction(&self, tx: KeyTransactionEntry) {
        self.pending_key_tx.write().push(tx);
    }

    /// 待打包密钥交易数量。
    pub fn get_pending_key_tx_count(&self) -> usize {
        self.pending_key_tx.read().len()
    }

    /// 加载待打包密钥交易(从存储恢复)。
    pub fn load_pending_key_tx(&self, txs: Vec<KeyTransactionEntry>) {
        *self.pending_key_tx.write() = txs;
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

    /// 回滚尚未完成持久化的挖矿结果。
    ///
    /// 挖矿和 SQLite 写入不是同一事务；调用方必须只在 save_block 失败时调用此方法。
    pub fn rollback_mined_block(&self, block: &Block) -> bool {
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

        // 一并回滚密钥交易,放回待打包队列头部,保持与元数据回滚一致的语义。
        let mut pending_key_tx = self.pending_key_tx.write();
        let mut restored_tx = block.key_transactions.clone();
        restored_tx.append(&mut *pending_key_tx);
        *pending_key_tx = restored_tx;
        drop(pending_key_tx);

        let mut pending_catalog = self.pending_catalog_records.write();
        let mut restored_catalog = block.catalog_records.clone();
        restored_catalog.append(&mut *pending_catalog);
        *pending_catalog = restored_catalog;
        true
    }

    /// 挖掘新区块
    pub fn mine_block(&self) -> Result<Block> {
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

        // 并入全部待打包密钥交易(backlog L1);它们会进入 merkle_root 受哈希保护。
        new_block.key_transactions = pending_key_tx.drain(..).collect();
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

        Ok(new_block)
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
        Self::validate_blocks(&blocks).is_ok()
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
        Self::validate_blocks(blocks)
    }

    /// 定位候选区块序列中第一个校验失败的区块索引。不改变 validate_blocks 本身的
    /// 校验规则,只是在已知失败的前提下复用相同规则逐块重放以报告具体位置,
    /// 供 `/chain/validate` 等需要展示 `invalid_block` 的场景使用。
    /// 链本身通过校验或为空时返回 None。
    pub fn find_first_invalid_block_index(blocks: &[Block]) -> Option<i64> {
        if blocks.is_empty() {
            return None;
        }
        let genesis = &blocks[0];
        if genesis.index != 0 || genesis.previous_hash != "0" {
            return Some(genesis.index);
        }
        for (position, block) in blocks.iter().enumerate() {
            let invalid = block.index != position as i64
                || block.hash != block.calculate_hash()
                || !block.is_valid()
                || block.merkle_root != block.calculate_merkle_root()
                || (position > 0 && block.previous_hash != blocks[position - 1].hash);
            if invalid {
                return Some(block.index);
            }
        }
        None
    }

    /// 以统一的完整规则验证候选区块序列。
    fn validate_blocks(blocks: &[Block]) -> Result<()> {
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
    use crate::catalog::{CatalogPayload, Subject};

    fn metadata_entry(data_id: &str) -> MetadataEntry {
        MetadataEntry {
            data_id: data_id.to_string(),
            data_size: 1,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            owner: "tester".to_string(),
            hashes: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            parent_id: None,
            tags: Vec::new(),
        }
    }

    fn valid_two_block_chain() -> Vec<Block> {
        let mut genesis = Block::new(0, "0".to_string(), 1);
        genesis.mine();
        let mut next = Block::new(1, genesis.hash.clone(), 1);
        next.mine();
        vec![genesis, next]
    }

    fn assert_validation_entrypoints_agree(blocks: Vec<Block>, expected_valid: bool) {
        let chain = Chain::new(1, 100);
        assert_eq!(
            chain.validate_loaded_blocks(&blocks).is_ok(),
            expected_valid,
            "validate_loaded_blocks 的结果不符合预期"
        );
        chain.load_blocks(blocks);
        assert_eq!(
            chain.validate_chain(),
            expected_valid,
            "validate_chain 的结果不符合预期"
        );
    }

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

    #[test]
    fn validate_chain_rejects_reminted_genesis_with_invalid_previous_hash() {
        let chain = Chain::new(1, 100);
        let mut genesis = Block::new(0, "not-the-genesis-parent".to_string(), 1);
        genesis.mine();
        chain.load_blocks(vec![genesis]);

        assert!(!chain.validate_chain());
    }

    #[test]
    fn validate_chain_rejects_metadata_tampered_after_mining() {
        let chain = Chain::new(1, 100);
        let mut genesis = Block::new(0, "0".to_string(), 1);
        genesis.add_metadata(metadata_entry("original-data-id"));
        genesis.mine();
        genesis.metadata_list[0].data_id = "tampered-data-id".to_string();
        chain.load_blocks(vec![genesis]);

        assert!(!chain.validate_chain());
    }

    #[test]
    fn validation_entrypoints_accept_valid_chain_and_reject_empty_chain() {
        assert_validation_entrypoints_agree(valid_two_block_chain(), true);
        assert_validation_entrypoints_agree(Vec::new(), false);
    }

    #[test]
    fn validation_entrypoints_reject_invalid_genesis_and_index_sequence() {
        let mut invalid_genesis_index = valid_two_block_chain();
        invalid_genesis_index[0].index = 1;
        invalid_genesis_index[0].mine();
        invalid_genesis_index[1].previous_hash = invalid_genesis_index[0].hash.clone();
        invalid_genesis_index[1].mine();
        assert_validation_entrypoints_agree(invalid_genesis_index, false);

        let mut invalid_genesis_parent = valid_two_block_chain();
        invalid_genesis_parent[0].previous_hash = "invalid-parent".to_string();
        invalid_genesis_parent[0].mine();
        invalid_genesis_parent[1].previous_hash = invalid_genesis_parent[0].hash.clone();
        invalid_genesis_parent[1].mine();
        assert_validation_entrypoints_agree(invalid_genesis_parent, false);

        let mut non_continuous_indexes = valid_two_block_chain();
        non_continuous_indexes[1].index = 2;
        non_continuous_indexes[1].mine();
        assert_validation_entrypoints_agree(non_continuous_indexes, false);
    }

    #[test]
    fn validation_entrypoints_reject_invalid_hash_pow_and_link() {
        let mut invalid_saved_hash = valid_two_block_chain();
        invalid_saved_hash[1].hash = "invalid-saved-hash".to_string();
        assert_validation_entrypoints_agree(invalid_saved_hash, false);

        let mut invalid_pow = valid_two_block_chain();
        invalid_pow[1].difficulty = 4;
        while invalid_pow[1]
            .calculate_hash()
            .starts_with(&"0".repeat(invalid_pow[1].difficulty as usize))
        {
            invalid_pow[1].nonce += 1;
        }
        invalid_pow[1].hash = invalid_pow[1].calculate_hash();
        assert!(
            !invalid_pow[1].is_valid(),
            "反例必须不满足该区块自身的 difficulty"
        );
        assert_validation_entrypoints_agree(invalid_pow, false);

        let mut invalid_link = valid_two_block_chain();
        invalid_link[1].previous_hash = "invalid-previous-hash".to_string();
        invalid_link[1].mine();
        assert_validation_entrypoints_agree(invalid_link, false);
    }

    #[test]
    fn validation_entrypoints_reject_tampered_merkle_payloads() {
        let mut invalid_metadata = valid_two_block_chain();
        invalid_metadata[1].add_metadata(metadata_entry("original-metadata"));
        invalid_metadata[1].mine();
        invalid_metadata[1].metadata_list[0].data_id = "tampered-metadata".to_string();
        assert_validation_entrypoints_agree(invalid_metadata, false);

        let mut invalid_key_transaction = valid_two_block_chain();
        invalid_key_transaction[1]
            .key_transactions
            .push(KeyTransactionEntry {
                tx_type: "register".to_string(),
                target_key: "original-key".to_string(),
                role: "node".to_string(),
                label: String::new(),
                signed_by: "original-key".to_string(),
                signature: "signature".to_string(),
                timestamp: 1,
                reason: String::new(),
            });
        invalid_key_transaction[1].mine();
        invalid_key_transaction[1].key_transactions[0].target_key = "tampered-key".to_string();
        assert_validation_entrypoints_agree(invalid_key_transaction, false);

        let mut invalid_catalog_record = valid_two_block_chain();
        invalid_catalog_record[1]
            .catalog_records
            .push(CatalogRecord {
                record_id: "record-1".to_string(),
                payload: CatalogPayload::Subject(Subject {
                    subject_id: "subject-1".to_string(),
                    subject_type: "repository".to_string(),
                    display_name: "Original subject".to_string(),
                    source_ref: String::new(),
                }),
                issuer_identity: "issuer".to_string(),
                issuer_key: "key".to_string(),
                signature: "signature".to_string(),
                recorded_at: 1,
            });
        invalid_catalog_record[1].mine();
        let CatalogPayload::Subject(subject) =
            &mut invalid_catalog_record[1].catalog_records[0].payload
        else {
            panic!("测试夹具应为 Subject 目录记录");
        };
        subject.display_name = "Tampered subject".to_string();
        assert_validation_entrypoints_agree(invalid_catalog_record, false);
    }
}
