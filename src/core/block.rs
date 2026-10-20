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

impl KeyTransactionEntry {
    /// 规范化签名/哈希负载:固定字段顺序拼接,不含 signature 与 timestamp,确保确定性。
    ///
    /// **不含 timestamp** 是有意为之:timestamp 由服务端在接收时盖(记录用),客户端提交前
    /// 无法预知,若纳入签名则客户端无法对其签名、服务端验签必然失败。故签名只覆盖语义字段
    /// (类型/目标公钥/角色/标签/发起方),timestamp 作为服务端记录的元信息不参与签名与叶子。
    pub fn signing_payload(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}|{}",
            self.tx_type, self.target_key, self.role, self.label, self.signed_by
        )
        .into_bytes()
    }

    /// merkle 叶子 = SHA256(规范化负载)的十六进制。
    pub fn leaf_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_payload());
        hex::encode(hasher.finalize())
    }
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

    /// 计算 Merkle 根。
    ///
    /// 叶子集合 = 元数据叶子 ++ 密钥交易叶子(backlog L1,选项 X):
    /// - 元数据叶子 = SHA256(data_id)(BLOCK_HASH_SPEC 第10节 v1,三版本一致)
    /// - 密钥交易叶子 = SHA256(规范化 key_tx)(见 `KeyTransactionEntry::leaf_hash`)
    ///
    /// 把 key_transactions 纳入 merkle_root,使身份/密钥交易与数据同等受区块哈希与
    /// PoW 保护,并可随 merkle_root 被外链锚定验证。向后兼容:key_transactions 为空时
    /// 不追加任何叶子,既有仅含元数据的区块 merkle_root 不变。
    pub fn calculate_merkle_root(&self) -> String {
        if self.metadata_list.is_empty() && self.key_transactions.is_empty() {
            return String::new();
        }

        let mut hashes: Vec<String> = self
            .metadata_list
            .iter()
            .map(|entry| super::metadata_leaf_hash(&entry.data_id))
            .collect();
        hashes.extend(self.key_transactions.iter().map(|tx| tx.leaf_hash()));

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

    fn sample_key_tx(target: &str) -> KeyTransactionEntry {
        KeyTransactionEntry {
            tx_type: "register".to_string(),
            target_key: target.to_string(),
            role: "node".to_string(),
            label: String::new(),
            signed_by: target.to_string(),
            signature: "sig".to_string(),
            timestamp: 100,
            reason: String::new(),
        }
    }

    #[test]
    fn key_transactions_enter_merkle_root_and_block_valid() {
        // 仅含密钥交易(无元数据)的区块:merkle_root 非空,挖矿后校验通过。
        let mut block = Block::new(1, "0".repeat(64), 2);
        block.key_transactions.push(sample_key_tx("pk-a"));
        block.mine();
        assert!(
            !block.merkle_root.is_empty(),
            "key_tx 应产生非空 merkle_root"
        );
        assert!(block.is_valid());
    }

    #[test]
    fn empty_block_merkle_root_unchanged_backward_compatible() {
        // 向后兼容:既无元数据也无密钥交易时 merkle_root 仍为空。
        let block = Block::new(1, "0".repeat(64), 2);
        assert_eq!(block.calculate_merkle_root(), "");
    }

    #[test]
    fn key_tx_leaf_hash_is_deterministic_and_signature_independent() {
        // 叶子哈希基于规范化负载(不含 signature),同内容不同签名叶子一致。
        let mut a = sample_key_tx("pk-a");
        let mut b = sample_key_tx("pk-a");
        a.signature = "sigA".to_string();
        b.signature = "sigB".to_string();
        assert_eq!(a.leaf_hash(), b.leaf_hash());
        let c = sample_key_tx("pk-b");
        assert_ne!(a.leaf_hash(), c.leaf_hash());
    }
}
