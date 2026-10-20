use std::sync::Arc;

use super::{CreateMetadataRequest, QueryMetadataRequest};
use crate::core::{Chain, MetadataEntry};
use crate::crypto::HashEngine;
use crate::error::Result;
use crate::storage::Storage;

/// 元数据管理器。
///
/// 写路径(create)仍把元数据加入链的待打包队列——区块里的 metadata_list 是**权威事实源**。
/// 读路径(query/get_*/statistics)改走 `metadata` 查询投影表(backlog #5),
/// 由 `Storage::commit_block` 在元数据上链时同事务写入、启动时回填补齐,
/// 避免每次查询都把整条链加载进内存做线性扫描。
///
/// 一致性边界:投影是只读副本,只覆盖**已上链**的元数据;尚在 pending(未挖矿)的
/// 元数据不出现在查询结果中(与此前基于已加载区块扫描的行为一致)。
pub struct MetadataManager {
    chain: Arc<Chain>,
    storage: Arc<Storage>,
    hash_engine: HashEngine,
}

impl MetadataManager {
    /// 创建元数据管理器
    pub fn new(chain: Arc<Chain>, storage: Arc<Storage>) -> Self {
        Self {
            chain,
            storage,
            hash_engine: HashEngine::new(None),
        }
    }

    /// 创建元数据(写路径:加入链的待打包队列,权威源)。保持同步、行为不变。
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

    /// 根据数据 ID 获取元数据(读投影)。
    pub async fn get_by_data_id(&self, data_id: &str) -> Result<Option<MetadataEntry>> {
        self.storage.get_metadata_by_id(data_id).await
    }

    /// 查询元数据(读投影)。owner / 时间范围下推 SQL;data_id / tag 过滤与分页在结果上做。
    pub async fn query(&self, req: &QueryMetadataRequest) -> Result<Vec<MetadataEntry>> {
        let mut results = self
            .storage
            .query_metadata(
                req.owner.as_deref(),
                req.start_time.map(|t| t.timestamp()),
                req.end_time.map(|t| t.timestamp()),
            )
            .await?;

        if let Some(data_id) = &req.data_id {
            results.retain(|e| &e.data_id == data_id);
        }
        if !req.tags.is_empty() {
            results.retain(|e| req.tags.iter().any(|t| e.tags.contains(t)));
        }

        // 分页
        let start = (req.page.saturating_sub(1)) * req.page_size;
        if start >= results.len() {
            return Ok(Vec::new());
        }
        let end = (start + req.page_size).min(results.len());
        Ok(results[start..end].to_vec())
    }

    /// 根据所有者获取元数据(读投影)。
    pub async fn get_by_owner(&self, owner: &str) -> Result<Vec<MetadataEntry>> {
        self.storage.query_metadata(Some(owner), None, None).await
    }

    /// 根据标签获取元数据(读投影 + 应用层 tag 过滤)。
    pub async fn get_by_tags(&self, tags: &[String]) -> Result<Vec<MetadataEntry>> {
        let all = self.storage.get_all_metadata().await?;
        Ok(all
            .into_iter()
            .filter(|e| tags.iter().any(|t| e.tags.contains(t)))
            .collect())
    }

    /// 获取所有元数据(读投影)。
    pub async fn get_all(&self) -> Result<Vec<MetadataEntry>> {
        self.storage.get_all_metadata().await
    }

    /// 获取统计信息(读投影;pending_count 仍取自链的待打包队列)。
    pub async fn get_statistics(&self) -> Result<MetadataStatistics> {
        let entries = self.storage.get_all_metadata().await?;

        let mut total_metadata = 0usize;
        let mut total_size: i64 = 0;
        let mut owners = std::collections::HashMap::new();
        let mut tags = std::collections::HashMap::new();

        for entry in &entries {
            total_metadata += 1;
            total_size += entry.data_size;
            *owners.entry(entry.owner.clone()).or_insert(0) += 1;
            for tag in &entry.tags {
                *tags.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        let mut top_owners: Vec<_> = owners.into_iter().collect();
        top_owners.sort_by(|a, b| b.1.cmp(&a.1));
        top_owners.truncate(10);

        let mut top_tags: Vec<_> = tags.into_iter().collect();
        top_tags.sort_by(|a, b| b.1.cmp(&a.1));
        top_tags.truncate(10);

        Ok(MetadataStatistics {
            total_metadata,
            total_size,
            unique_owners: top_owners.len(),
            pending_count: self.chain.get_pending_count(),
            top_owners,
            top_tags,
        })
    }

    /// 验证哈希(读投影取条目)。
    pub async fn verify_hash(
        &self,
        data_id: &str,
        content: &[u8],
        algorithm: &str,
    ) -> Result<bool> {
        if let Some(entry) = self.get_by_data_id(data_id).await? {
            if let Some(stored_hash) = entry.hashes.get(algorithm) {
                let computed_hash = self.hash_engine.compute_hash(content, algorithm);
                return Ok(&computed_hash == stored_hash);
            }
        }
        Ok(false)
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
pub fn create_metadata_manager(chain: Arc<Chain>, storage: Arc<Storage>) -> Arc<MetadataManager> {
    Arc::new(MetadataManager::new(chain, storage))
}
