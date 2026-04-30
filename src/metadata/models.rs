use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 数据元信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMetadata {
    pub data_id: String,
    pub data_size: i64,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub owner: String,
    pub hashes: HashMap<String, String>,
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub block_index: i64,
    pub status: MetadataStatus,
}

/// 元数据状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataStatus {
    Active,
    Deleted,
}

impl Default for MetadataStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl DataMetadata {
    /// 创建新的元数据
    pub fn new(data_size: i64, owner: String) -> Self {
        let now = Utc::now();
        Self {
            data_id: uuid::Uuid::new_v4().to_string(),
            data_size,
            created_at: now,
            modified_at: now,
            owner,
            hashes: HashMap::new(),
            extra: HashMap::new(),
            parent_id: None,
            tags: Vec::new(),
            block_index: -1,
            status: MetadataStatus::Active,
        }
    }

    /// 添加标签
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.modified_at = Utc::now();
        }
    }

    /// 移除标签
    pub fn remove_tag(&mut self, tag: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.modified_at = Utc::now();
        }
    }

    /// 检查是否有标签
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(&tag.to_string())
    }

    /// 软删除
    pub fn soft_delete(&mut self) {
        self.status = MetadataStatus::Deleted;
        self.modified_at = Utc::now();
    }

    /// 恢复
    pub fn restore(&mut self) {
        self.status = MetadataStatus::Active;
        self.modified_at = Utc::now();
    }

    /// 检查是否为活跃状态
    pub fn is_active(&self) -> bool {
        self.status == MetadataStatus::Active
    }

    /// 设置哈希值
    pub fn set_hash(&mut self, algorithm: String, hash: String) {
        self.hashes.insert(algorithm, hash);
        self.modified_at = Utc::now();
    }

    /// 获取哈希值
    pub fn get_hash(&self, algorithm: &str) -> Option<&String> {
        self.hashes.get(algorithm)
    }

    /// 设置扩展元数据
    pub fn set_extra(&mut self, key: String, value: serde_json::Value) {
        self.extra.insert(key, value);
        self.modified_at = Utc::now();
    }

    /// 获取扩展元数据
    pub fn get_extra(&self, key: &str) -> Option<&serde_json::Value> {
        self.extra.get(key)
    }

    /// 克隆元数据（创建新版本）
    pub fn clone_as_new_version(&self) -> Self {
        let now = Utc::now();
        Self {
            data_id: uuid::Uuid::new_v4().to_string(),
            data_size: self.data_size,
            created_at: now,
            modified_at: now,
            owner: self.owner.clone(),
            hashes: self.hashes.clone(),
            extra: self.extra.clone(),
            parent_id: Some(self.data_id.clone()),
            tags: self.tags.clone(),
            block_index: -1,
            status: MetadataStatus::Active,
        }
    }
}

/// 创建元数据请求
#[derive(Debug, Clone, Deserialize)]
pub struct CreateMetadataRequest {
    pub data_size: i64,
    pub owner: Option<String>,
    #[serde(default)]
    pub hashes: HashMap<String, String>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    pub parent_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(skip)]
    pub content: Option<Vec<u8>>,
}

/// 查询元数据请求
#[derive(Debug, Clone, Deserialize)]
pub struct QueryMetadataRequest {
    pub data_id: Option<String>,
    pub owner: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_page")]
    pub page: usize,
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_page() -> usize { 1 }
fn default_page_size() -> usize { 20 }
