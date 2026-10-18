//! 跨链锚定（Cross-chain Anchoring）。
//!
//! DataChain 不直接把区块复制到其他链，而是生成一份 **ChainAnchor**：
//! 包含源链身份、目标链标识、被锚定数据的 Merkle 根与证明，并由本节点
//! ed25519 私钥签名。目标链（或 attestation 服务）收到后存证并回执
//! **AnchorReceipt**。目标链可凭源节点公钥独立验签，无需信任传输通道。
//!
//! 可靠投递依赖 `anchor_outbox` 表：锚定先落库（pending），由后台 worker
//! 带退避重试投递到目标链，成功后记录回执，失败累计次数。进程重启后
//! 未完成的锚定可从库中恢复继续投递。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::core::MerkleProof;
use crate::error::{DataChainError, Result};
use crate::node_signing::NodeIdentity;
use crate::storage::Storage;

/// 锚定投递状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorStatus {
    /// 待投递。
    Pending,
    /// 已成功投递并取得回执。
    Confirmed,
    /// 超过最大重试次数，放弃。
    Failed,
}

impl AnchorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnchorStatus::Pending => "pending",
            AnchorStatus::Confirmed => "confirmed",
            AnchorStatus::Failed => "failed",
        }
    }

    pub fn parse_status(s: &str) -> Self {
        match s {
            "confirmed" => AnchorStatus::Confirmed,
            "failed" => AnchorStatus::Failed,
            _ => AnchorStatus::Pending,
        }
    }
}

/// 跨链锚定载荷：描述"源链某数据已上链"这一事实，供目标链存证。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnchor {
    /// 锚定唯一 ID。
    pub anchor_id: String,
    /// 源链标识。
    pub source_chain_id: String,
    /// 源节点 ID。
    pub source_node_id: String,
    /// 目标链标识。
    pub target_chain_id: String,
    /// 被锚定的数据 ID。
    pub data_id: String,
    /// 源区块哈希。
    pub block_hash: String,
    /// 源区块 Merkle 根。
    pub merkle_root: String,
    /// 数据在该区块中的 Merkle 证明（目标链可独立验证 data→root）。
    pub proof: MerkleProof,
    /// 生成时间。
    pub created_at: DateTime<Utc>,
}

impl ChainAnchor {
    /// 生成签名所覆盖的规范字节（不含签名本身，确保确定性）。
    pub fn signing_payload(&self) -> Vec<u8> {
        // 固定字段顺序拼接，避免依赖 JSON 字段序的不确定性。
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.anchor_id,
            self.source_chain_id,
            self.source_node_id,
            self.target_chain_id,
            self.data_id,
            self.block_hash,
            self.merkle_root,
            self.proof.root,
        )
        .into_bytes()
    }
}

/// 已签名锚定：锚定载荷 + 源节点公钥 + 签名，可整体传输给目标链。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChainAnchor {
    pub anchor: ChainAnchor,
    /// 源节点 ed25519 公钥（base64）。
    pub public_key: String,
    /// 对 `anchor.signing_payload()` 的 ed25519 签名（base64）。
    pub signature: String,
}

impl SignedChainAnchor {
    /// 验证签名与公钥是否匹配锚定内容。
    pub fn verify(&self) -> Result<bool> {
        NodeIdentity::verify_base64(
            &self.public_key,
            &self.anchor.signing_payload(),
            &self.signature,
        )
    }
}

/// 目标链/attestation 服务返回的回执。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReceipt {
    pub anchor_id: String,
    pub target_chain_id: String,
    /// 目标链上的交易/存证引用（如交易哈希、存证 ID）。
    pub target_ref: String,
    pub confirmed_at: DateTime<Utc>,
}

/// outbox 行：锚定及其投递状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorOutboxEntry {
    pub signed: SignedChainAnchor,
    pub status: AnchorStatus,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub receipt: Option<AnchorReceipt>,
    pub updated_at: DateTime<Utc>,
}

/// 目标链投递抽象：便于测试与多后端。
#[async_trait::async_trait]
pub trait AnchorConnector: Send + Sync {
    /// 投递已签名锚定，成功返回回执。
    async fn deliver(&self, signed: &SignedChainAnchor) -> Result<AnchorReceipt>;
}

/// 基于 HTTP 的 attestation 连接器：把锚定 POST 到目标链/存证服务端点。
pub struct HttpAttestationConnector {
    client: reqwest::Client,
    endpoint: String,
    auth_token: Option<String>,
}

impl HttpAttestationConnector {
    pub fn new(endpoint: impl Into<String>, auth_token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            endpoint: endpoint.into(),
            auth_token,
        }
    }
}

#[async_trait::async_trait]
impl AnchorConnector for HttpAttestationConnector {
    async fn deliver(&self, signed: &SignedChainAnchor) -> Result<AnchorReceipt> {
        let mut request = self.client.post(&self.endpoint).json(signed);
        if let Some(token) = &self.auth_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|e| DataChainError::StorageError(format!("锚定投递请求失败: {}", e)))?;
        if !response.status().is_success() {
            return Err(DataChainError::StorageError(format!(
                "目标链返回 HTTP {}",
                response.status()
            )));
        }
        let receipt = response
            .json::<AnchorReceipt>()
            .await
            .map_err(|e| DataChainError::StorageError(format!("无效的回执响应: {}", e)))?;
        Ok(receipt)
    }
}

/// 跨链锚定服务：生成签名锚定、写 outbox、驱动重试投递。
pub struct AnchorService {
    identity: Arc<NodeIdentity>,
    chain_id: String,
    default_target_chain_id: String,
    storage: Arc<Storage>,
    connector: Option<Arc<dyn AnchorConnector>>,
    max_attempts: i64,
}

impl AnchorService {
    pub fn new(
        identity: Arc<NodeIdentity>,
        chain_id: impl Into<String>,
        storage: Arc<Storage>,
        connector: Option<Arc<dyn AnchorConnector>>,
    ) -> Self {
        Self {
            identity,
            chain_id: chain_id.into(),
            default_target_chain_id: "attestation-service".to_string(),
            storage,
            connector,
            max_attempts: 8,
        }
    }

    /// 设置默认目标链标识（API 未显式指定 target 时使用）。
    pub fn with_default_target_chain_id(mut self, target: impl Into<String>) -> Self {
        self.default_target_chain_id = target.into();
        self
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn default_target_chain_id(&self) -> &str {
        &self.default_target_chain_id
    }

    pub fn node_identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// 由 Merkle 证明生成签名锚定并写入 outbox（pending）。
    pub async fn enqueue_anchor(
        &self,
        target_chain_id: impl Into<String>,
        data_id: impl Into<String>,
        block_hash: impl Into<String>,
        merkle_root: impl Into<String>,
        proof: MerkleProof,
    ) -> Result<SignedChainAnchor> {
        let anchor = ChainAnchor {
            anchor_id: uuid::Uuid::new_v4().to_string(),
            source_chain_id: self.chain_id.clone(),
            source_node_id: self.identity.node_id().to_string(),
            target_chain_id: target_chain_id.into(),
            data_id: data_id.into(),
            block_hash: block_hash.into(),
            merkle_root: merkle_root.into(),
            proof,
            created_at: Utc::now(),
        };
        let signature = self.identity.sign_base64(&anchor.signing_payload());
        let signed = SignedChainAnchor {
            anchor,
            public_key: self.identity.public_key_base64(),
            signature,
        };
        self.storage.enqueue_anchor(&signed).await?;
        Ok(signed)
    }

    /// 处理一批待投递锚定。返回本轮成功投递的数量。
    pub async fn process_pending(&self) -> Result<usize> {
        let connector = match &self.connector {
            Some(c) => c.clone(),
            None => return Ok(0),
        };
        let pending = self.storage.list_pending_anchors(32).await?;
        let mut confirmed = 0usize;
        for entry in pending {
            let anchor_id = entry.signed.anchor.anchor_id.clone();
            match connector.deliver(&entry.signed).await {
                Ok(receipt) => {
                    self.storage
                        .mark_anchor_confirmed(&anchor_id, &receipt)
                        .await?;
                    confirmed += 1;
                }
                Err(e) => {
                    let attempts = entry.attempts + 1;
                    let status = if attempts >= self.max_attempts {
                        AnchorStatus::Failed
                    } else {
                        AnchorStatus::Pending
                    };
                    self.storage
                        .mark_anchor_attempt(&anchor_id, attempts, status, &e.to_string())
                        .await?;
                    tracing::warn!("锚定 {} 投递失败(第 {} 次): {}", anchor_id, attempts, e);
                }
            }
        }
        Ok(confirmed)
    }

    /// 启动后台重试 worker（固定间隔 + 库内 attempts 计数作为退避依据）。
    pub fn start_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if self.connector.is_none() {
                    continue;
                }
                if let Err(e) = self.process_pending().await {
                    tracing::warn!("锚定 outbox 处理失败: {}", e);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::MerkleProof;

    fn sample_proof() -> MerkleProof {
        MerkleProof {
            root: "root-hash".to_string(),
            leaf: "leaf-hash".to_string(),
            leaf_index: 0,
            siblings: vec!["sib".to_string()],
            sibling_is_left: vec![false],
        }
    }

    #[test]
    fn signed_anchor_verifies() {
        let identity = NodeIdentity::generate("node-a");
        let anchor = ChainAnchor {
            anchor_id: "a1".to_string(),
            source_chain_id: "datachain-main".to_string(),
            source_node_id: "node-a".to_string(),
            target_chain_id: "target-x".to_string(),
            data_id: "d1".to_string(),
            block_hash: "bh".to_string(),
            merkle_root: "root-hash".to_string(),
            proof: sample_proof(),
            created_at: Utc::now(),
        };
        let signature = identity.sign_base64(&anchor.signing_payload());
        let signed = SignedChainAnchor {
            anchor,
            public_key: identity.public_key_base64(),
            signature,
        };
        assert!(signed.verify().unwrap());
    }

    #[test]
    fn tampered_anchor_fails_verification() {
        let identity = NodeIdentity::generate("node-a");
        let anchor = ChainAnchor {
            anchor_id: "a1".to_string(),
            source_chain_id: "datachain-main".to_string(),
            source_node_id: "node-a".to_string(),
            target_chain_id: "target-x".to_string(),
            data_id: "d1".to_string(),
            block_hash: "bh".to_string(),
            merkle_root: "root-hash".to_string(),
            proof: sample_proof(),
            created_at: Utc::now(),
        };
        let signature = identity.sign_base64(&anchor.signing_payload());
        let mut signed = SignedChainAnchor {
            anchor,
            public_key: identity.public_key_base64(),
            signature,
        };
        signed.anchor.data_id = "d2".to_string();
        assert!(!signed.verify().unwrap());
    }
}
