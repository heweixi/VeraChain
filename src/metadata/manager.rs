use std::sync::Arc;

use super::{CreateMetadataRequest, QueryMetadataRequest};
use crate::core::{Chain, MetadataEntry};
use crate::crypto::HashEngine;
use crate::error::Result;

/// 元数据管理器
pub struct MetadataManager {
    chain: Arc<Chain>,
    hash_engine: HashEngine,
}

impl MetadataManager {
    /// 创建元数据管理器
    pub fn new(chain: Arc<Chain>) -> Self {
        Self {
            chain,
            hash_engine: HashEngine::new(None),
        }
    }

    /// 创建元数据
    pub fn create(&self, req: &CreateMetadataRequest, username: &str) -> Result<MetadataEntry> {
        let owner = req.owner.clone().unwrap_or_else(|| username.to_string());

        let mut entry = MetadataEntry {
            data_id: uuid::Uuid::new_v4().to_string(),
            data_size: req.data_size,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            owner,
            hashes: req.hashes.clone(),
            metadata: req.metadata.clone(),
            parent_id: req.parent_id.clone(),
            tags: req.tags.clone(),
        };

        // 如果提供了内容，计算哈希
        if let Some(content) = &req.content {
            entry.hashes = self.hash_engine.compute_fast_hashes(content);
        }

        // 添加到待打包队列
        self.chain.add_metadata(entry.clone());

        Ok(entry)
    }

    /// 创建元数据（计算快速哈希）
    pub fn create_with_fast_hash(
        &self,
        req: &CreateMetadataRequest,
        username: &str,
    ) -> Result<MetadataEntry> {
        self.create(req, username)
    }

    /// 根据数据 ID 获取元数据
    pub fn get_by_data_id(&self, data_id: &str) -> Option<MetadataEntry> {
        let blocks = self.chain.get_all_blocks();
        for block in blocks {
            for entry in &block.metadata_list {
                if entry.data_id == data_id {
                    return Some(entry.clone());
                }
            }
        }
        None
    }

    /// 查询元数据
    pub fn query(&self, req: &QueryMetadataRequest) -> Vec<MetadataEntry> {
        let mut results = Vec::new();

        let blocks = self.chain.get_all_blocks();
        for block in blocks {
            for entry in &block.metadata_list {
                if self.match_entry(entry, req) {
                    results.push(entry.clone());
                }
            }
        }

        // 分页
        let start = (req.page - 1) * req.page_size;
        if start >= results.len() {
            return Vec::new();
        }
        let end = (start + req.page_size).min(results.len());
        results[start..end].to_vec()
    }

    /// 匹配元数据条目
    fn match_entry(&self, entry: &MetadataEntry, req: &QueryMetadataRequest) -> bool {
        if let Some(data_id) = &req.data_id {
            if &entry.data_id != data_id {
                return false;
            }
        }

        if let Some(owner) = &req.owner {
            if &entry.owner != owner {
                return false;
            }
        }

        if let Some(start_time) = req.start_time {
            if entry.created_at < start_time {
                return false;
            }
        }

        if let Some(end_time) = req.end_time {
            if entry.created_at > end_time {
                return false;
            }
        }

        if !req.tags.is_empty() {
            let has_any_tag = req.tags.iter().any(|t| entry.tags.contains(t));
            if !has_any_tag {
                return false;
            }
        }

        true
    }

    /// 根据所有者获取元数据
    pub fn get_by_owner(&self, owner: &str) -> Vec<MetadataEntry> {
        let mut results = Vec::new();

        let blocks = self.chain.get_all_blocks();
        for block in blocks {
            for entry in &block.metadata_list {
                if entry.owner == owner {
                    results.push(entry.clone());
                }
            }
        }

        results
    }

    /// 根据标签获取元数据
    pub fn get_by_tags(&self, tags: &[String]) -> Vec<MetadataEntry> {
        let mut results = Vec::new();

        let blocks = self.chain.get_all_blocks();
        for block in blocks {
            for entry in &block.metadata_list {
                let has_any_tag = tags.iter().any(|t| entry.tags.contains(t));
                if has_any_tag {
                    results.push(entry.clone());
                }
            }
        }

        results
    }

    /// 获取所有元数据
    pub fn get_all(&self) -> Vec<MetadataEntry> {
        let mut results = Vec::new();

        let blocks = self.chain.get_all_blocks();
        for block in blocks {
            results.extend(block.metadata_list.clone());
        }

        results
    }

    /// 获取统计信息
    pub fn get_statistics(&self) -> MetadataStatistics {
        let mut total_metadata = 0;
        let mut total_size: i64 = 0;
        let mut owners = std::collections::HashMap::new();
        let mut tags = std::collections::HashMap::new();

        let blocks = self.chain.get_all_blocks();
        for block in blocks {
            for entry in &block.metadata_list {
                total_metadata += 1;
                total_size += entry.data_size;
                *owners.entry(entry.owner.clone()).or_insert(0) += 1;

                for tag in &entry.tags {
                    *tags.entry(tag.clone()).or_insert(0) += 1;
                }
            }
        }

        // Top owners
        let mut top_owners: Vec<_> = owners.into_iter().collect();
        top_owners.sort_by(|a, b| b.1.cmp(&a.1));
        top_owners.truncate(10);

        // Top tags
        let mut top_tags: Vec<_> = tags.into_iter().collect();
        top_tags.sort_by(|a, b| b.1.cmp(&a.1));
        top_tags.truncate(10);

        MetadataStatistics {
            total_metadata,
            total_size,
            unique_owners: top_owners.len(),
            pending_count: self.chain.get_pending_count(),
            top_owners,
            top_tags,
        }
    }

    /// 验证哈希
    pub fn verify_hash(&self, data_id: &str, content: &[u8], algorithm: &str) -> bool {
        if let Some(entry) = self.get_by_data_id(data_id) {
            if let Some(stored_hash) = entry.hashes.get(algorithm) {
                let computed_hash = self.hash_engine.compute_hash(content, algorithm);
                return &computed_hash == stored_hash;
            }
        }
        false
    }
}

/// 元数据统计
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetadataStatistics {
    pub total_metadata: usize,
    pub total_size: i64,
    pub unique_owners: usize,
    pub pending_count: usize,
    pub top_owners: Vec<(String, usize)>,
    pub top_tags: Vec<(String, usize)>,
}

/// 创建共享的 MetadataManager 实例
pub fn create_metadata_manager(chain: Arc<Chain>) -> Arc<MetadataManager> {
    Arc::new(MetadataManager::new(chain))
}
