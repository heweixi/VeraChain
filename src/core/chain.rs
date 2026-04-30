use chrono::{TimeZone, Utc};
use parking_lot::RwLock;
use std::sync::Arc;

use super::block::{Block, MetadataEntry};
use crate::error::{DataChainError, Result};

/// 区块链
pub struct Chain {
    blocks: RwLock<Vec<Block>>,
    difficulty: u32,
    block_size: usize,
    pending: RwLock<Vec<MetadataEntry>>,
}

impl Chain {
    /// 创建新的区块链
    pub fn new(difficulty: u32, block_size: usize) -> Self {
        Self {
            blocks: RwLock::new(Vec::new()),
            difficulty,
            block_size,
            pending: RwLock::new(Vec::new()),
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

    /// 挖掘新区块
    pub fn mine_block(&self) -> Result<Block> {
        let blocks = self.blocks.read();
        if blocks.is_empty() {
            return Err(DataChainError::ChainNotInitialized);
        }

        let mut pending = self.pending.write();
        if pending.is_empty() {
            return Err(DataChainError::AggregationFailed("no pending metadata".to_string()));
        }

        let latest = blocks.last().unwrap();
        let mut new_block = Block::new(latest.index + 1, latest.hash.clone(), self.difficulty);

        // 添加待打包的元数据
        let count = self.block_size.min(pending.len());
        for entry in pending.drain(..count) {
            new_block.add_metadata(entry);
        }

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
            return Err(DataChainError::InvalidBlock("invalid previous hash".to_string()));
        }
        if !block.is_valid() {
            return Err(DataChainError::InvalidBlock("invalid proof of work".to_string()));
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

    /// 加载区块（从存储恢复）
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
}
