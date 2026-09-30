use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::merkle::build_merkle_root;

/// 元数据条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    pub data_id: String,
    pub data_size: i64,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub owner: String,
    pub hashes: HashMap<String, String>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// 汇总信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationInfo {
    pub summary_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    pub statistics: HashMap<String, serde_json::Value>,
    pub merkle_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_range: Option<(i64, i64)>,
}

/// 时间范围
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// 版本信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version_id: String,
    pub timestamp: DateTime<Utc>,
    pub files: Vec<FileVersion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_version: Option<String>,
}

/// 文件版本
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersion {
    pub path: String,
    pub hash: String,
    pub size: i64,
    pub content_hash: String,
}

/// 区块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: i64,
    pub timestamp: DateTime<Utc>,
    pub previous_hash: String,
    pub merkle_root: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub hash: String,
    #[serde(default)]
    pub metadata_list: Vec<MetadataEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<AggregationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
    // === Attestation fields (Requirement 9) ===
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<SignedAttestation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_transactions: Vec<KeyTransactionEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_registry: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity_snapshot_hash: String,
}

/// 带签名的认证记录 (Requirement 9.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub hash_bundle: HashMap<String, serde_json::Value>,
    pub submitter_key: String,
    pub signature: String,
    pub timestamp: i64,
}

/// 密钥管理交易 (Requirement 9.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTransactionEntry {
    #[serde(rename = "type")]
    pub tx_type: String,
    pub target_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    pub signed_by: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

impl Block {
    /// 创建新区块
    pub fn new(index: i64, previous_hash: String, difficulty: u32) -> Self {
        Self {
            index,
            timestamp: Utc::now(),
            previous_hash,
            merkle_root: String::new(),
            nonce: 0,
            difficulty,
            hash: String::new(),
            metadata_list: Vec::new(),
            aggregation: None,
            version_info: None,
            attestations: Vec::new(),
            key_transactions: Vec::new(),
            identity_registry: None,
            identity_snapshot_hash: String::new(),
        }
    }

    /// 添加元数据
    pub fn add_metadata(&mut self, entry: MetadataEntry) {
        self.metadata_list.push(entry);
    }

    /// 计算区块哈希(遵循统一规范 BLOCK_HASH_SPEC.md v1)。
    ///
    /// 统一算法只哈希区块头字段 + merkle_root(负载完整性由 merkle_root 承载),
    /// timestamp 归一化为 Unix 秒,确保与 Python/Go 实现字节级一致。
    pub fn calculate_hash(&self) -> String {
        super::canonical_block_hash(
            self.index,
            self.timestamp.timestamp(),
            &self.previous_hash,
            &self.merkle_root,
            self.nonce,
            self.difficulty,
        )
    }

    /// 计算 Merkle 根
    pub fn calculate_merkle_root(&self) -> String {
        if self.metadata_list.is_empty() {
            return String::new();
        }

        // 叶子 = SHA256(data_id)(BLOCK_HASH_SPEC 第10节 v1,三版本一致)
        let hashes: Vec<String> = self
            .metadata_list
            .iter()
            .map(|entry| super::metadata_leaf_hash(&entry.data_id))
            .collect();

        build_merkle_root(&hashes)
    }

    /// 挖矿（工作量证明）
    pub fn mine(&mut self) {
        self.merkle_root = self.calculate_merkle_root();
        let target = "0".repeat(self.difficulty as usize);

        loop {
            self.hash = self.calculate_hash();
            if self.hash.starts_with(&target) {
                break;
            }
            self.nonce += 1;
        }
    }

    /// 验证区块
    pub fn is_valid(&self) -> bool {
        let target = "0".repeat(self.difficulty as usize);
        self.hash == self.calculate_hash() && self.hash.starts_with(&target)
    }

    /// 序列化为 JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// 从 JSON 反序列化
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_block() {
        let block = Block::new(0, "0".to_string(), 2);
        assert_eq!(block.index, 0);
        assert_eq!(block.previous_hash, "0");
        assert_eq!(block.difficulty, 2);
    }

    #[test]
    fn test_mine_block() {
        let mut block = Block::new(0, "0".to_string(), 2);
        block.mine();
        assert!(block.hash.starts_with("00"));
    }

    #[test]
    fn test_block_validation() {
        let mut block = Block::new(0, "0".to_string(), 2);
        block.mine();
        assert!(block.is_valid());
    }
}
