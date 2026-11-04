//! 可验证语义目录：Subject → Revision → Artifact 与可撤销认证声明(Claim)。
//!
//! 该模块解决普通 metadata 仅以 `data_id` 作为 Merkle 叶子、无法直接证明其完整语义的
//! 局限。新的目录记录使用固定字段顺序生成语义承诺，作为区块 Merkle 叶子进入链；
//! 旧 metadata 区块保持原有规则，避免重写历史或破坏兼容性。
//!
//! 设计原则：
//! - Subject 是长期稳定的逻辑对象（文章、代码库、软件包或其他跟踪事物）；
//! - Revision 是不可变内容版本；Artifact 是同一版本的构建/配置变体；
//! - Claim 是认证者带签名、证据和时间范围的声明，不可原地修改，只能补充、撤销或覆盖；
//! - 当前状态由链上记录重放或查询投影得出，区块记录才是权威事实源。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{DataChainError, Result};
use crate::node_signing::NodeIdentity;

pub const CATALOG_RECORD_VERSION: &str = "catalog-v1";

/// 逻辑对象：一篇文章、一个代码库、一个软件包或任意长期被追踪事物。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub subject_id: String,
    pub subject_type: String,
    pub display_name: String,
    #[serde(default)]
    pub source_ref: String,
}

/// 不可变内容版本。相同内容可用内容哈希识别，parent_revision_id 表示演进关系。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub revision_id: String,
    pub subject_id: String,
    pub content_hash: String,
    #[serde(default)]
    pub parent_revision_id: String,
    #[serde(default)]
    pub source_ref: String,
}

/// 同一 Revision 的构建或配置变体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub revision_id: String,
    pub artifact_hash: String,
    #[serde(default)]
    pub configuration_hash: String,
    #[serde(default)]
    pub platform: String,
}

/// 带来源、证据、时间范围及生命周期状态的认证声明。
///
/// category 建议采用命名空间，例如 support.lts、quality.verified、risk.vulnerability、
/// risk.malware。status 可表示 reported/confirmed/disputed/resolved/withdrawn/superseded 等。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    #[serde(default)]
    pub subject_id: String,
    #[serde(default)]
    pub revision_id: String,
    #[serde(default)]
    pub artifact_id: String,
    pub category: String,
    pub status: String,
    pub evidence_ref: String,
    pub observed_at: i64,
    #[serde(default)]
    pub effective_from: Option<i64>,
    #[serde(default)]
    pub effective_to: Option<i64>,
    #[serde(default)]
    pub supersedes_claim_id: String,
}

/// 一条目录记录的业务负载。`type` 是稳定的语义类别，参与签名和 Merkle 承诺。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CatalogPayload {
    Subject(Subject),
    Revision(Revision),
    Artifact(Artifact),
    Claim(Claim),
}

/// 客户端提交目录记录时提供的内容。record_id 和 recorded_at 均由本链服务端生成，
/// 不让客户端预测；签名覆盖全部业务语义、认证者身份与公钥。
#[derive(Debug, Clone, Deserialize)]
pub struct CatalogRecordRequest {
    pub payload: CatalogPayload,
    pub issuer_identity: String,
    pub issuer_key: String,
    pub signature: String,
}

/// 已验证、可进入待打包队列的链上目录记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogRecord {
    pub record_id: String,
    pub payload: CatalogPayload,
    pub issuer_identity: String,
    pub issuer_key: String,
    pub signature: String,
    pub recorded_at: i64,
}

impl CatalogPayload {
    pub fn record_type(&self) -> &'static str {
        match self {
            CatalogPayload::Subject(_) => "subject",
            CatalogPayload::Revision(_) => "revision",
            CatalogPayload::Artifact(_) => "artifact",
            CatalogPayload::Claim(_) => "claim",
        }
    }

    /// 该语义对象的稳定主标识。一个主标识只能首次定义一次；后续状态变化应以 Claim 表达。
    pub fn primary_id(&self) -> &str {
        match self {
            CatalogPayload::Subject(v) => &v.subject_id,
            CatalogPayload::Revision(v) => &v.revision_id,
            CatalogPayload::Artifact(v) => &v.artifact_id,
            CatalogPayload::Claim(v) => &v.claim_id,
        }
    }

    /// 按固定字段顺序给出业务字段；可选字段用空字符串表示，外层长度前缀消除歧义。
    fn canonical_fields(&self) -> Vec<String> {
        match self {
            CatalogPayload::Subject(v) => vec![
                v.subject_id.clone(),
                v.subject_type.clone(),
                v.display_name.clone(),
                v.source_ref.clone(),
            ],
            CatalogPayload::Revision(v) => vec![
                v.revision_id.clone(),
                v.subject_id.clone(),
                v.content_hash.clone(),
                v.parent_revision_id.clone(),
                v.source_ref.clone(),
            ],
            CatalogPayload::Artifact(v) => vec![
                v.artifact_id.clone(),
                v.revision_id.clone(),
                v.artifact_hash.clone(),
                v.configuration_hash.clone(),
                v.platform.clone(),
            ],
            CatalogPayload::Claim(v) => vec![
                v.claim_id.clone(),
                v.subject_id.clone(),
                v.revision_id.clone(),
                v.artifact_id.clone(),
                v.category.clone(),
                v.status.clone(),
                v.evidence_ref.clone(),
                v.observed_at.to_string(),
                v.effective_from.map(|x| x.to_string()).unwrap_or_default(),
                v.effective_to.map(|x| x.to_string()).unwrap_or_default(),
                v.supersedes_claim_id.clone(),
            ],
        }
    }

    fn validate(&self) -> Result<()> {
        let nonempty = |value: &str, name: &str| -> Result<()> {
            if value.trim().is_empty() {
                return Err(DataChainError::InvalidBlock(format!(
                    "catalog {} must not be empty",
                    name
                )));
            }
            Ok(())
        };
        match self {
            CatalogPayload::Subject(v) => {
                nonempty(&v.subject_id, "subject_id")?;
                nonempty(&v.subject_type, "subject_type")?;
                nonempty(&v.display_name, "display_name")?;
            }
            CatalogPayload::Revision(v) => {
                nonempty(&v.revision_id, "revision_id")?;
                nonempty(&v.subject_id, "subject_id")?;
                nonempty(&v.content_hash, "content_hash")?;
            }
            CatalogPayload::Artifact(v) => {
                nonempty(&v.artifact_id, "artifact_id")?;
                nonempty(&v.revision_id, "revision_id")?;
                nonempty(&v.artifact_hash, "artifact_hash")?;
            }
            CatalogPayload::Claim(v) => {
                nonempty(&v.claim_id, "claim_id")?;
                if v.subject_id.is_empty() && v.revision_id.is_empty() && v.artifact_id.is_empty() {
                    return Err(DataChainError::InvalidBlock(
                        "claim must target a subject, revision, or artifact".to_string(),
                    ));
                }
                nonempty(&v.category, "claim category")?;
                nonempty(&v.status, "claim status")?;
                nonempty(&v.evidence_ref, "claim evidence_ref")?;
                if let (Some(from), Some(to)) = (v.effective_from, v.effective_to) {
                    if from > to {
                        return Err(DataChainError::InvalidBlock(
                            "claim effective_from must not be after effective_to".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl CatalogRecord {
    /// 客户端预签名的确定性负载。record_id/recorded_at 由服务端盖章，不参与签名。
    pub fn request_signing_payload(
        payload: &CatalogPayload,
        issuer_identity: &str,
        issuer_key: &str,
    ) -> Vec<u8> {
        let mut fields = vec![
            CATALOG_RECORD_VERSION.to_string(),
            payload.record_type().to_string(),
            issuer_identity.to_string(),
            issuer_key.to_string(),
        ];
        fields.extend(payload.canonical_fields());
        // 每个字段 length:value，避免值内含 | / 空串导致边界歧义。
        fields
            .into_iter()
            .map(|field| format!("{}:{}", field.len(), field))
            .collect::<Vec<_>>()
            .join("|")
            .into_bytes()
    }

    /// 校验签名并创建服务端盖章后的记录。
    pub fn from_verified_request(req: CatalogRecordRequest, recorded_at: i64) -> Result<Self> {
        req.payload.validate()?;
        if req.issuer_identity.trim().is_empty() || req.issuer_key.trim().is_empty() {
            return Err(DataChainError::InvalidBlock(
                "catalog issuer_identity/issuer_key must not be empty".to_string(),
            ));
        }
        let bytes =
            Self::request_signing_payload(&req.payload, &req.issuer_identity, &req.issuer_key);
        if !NodeIdentity::verify_base64(&req.issuer_key, &bytes, &req.signature)? {
            return Err(DataChainError::InvalidToken);
        }
        Ok(Self {
            record_id: uuid::Uuid::new_v4().to_string(),
            payload: req.payload,
            issuer_identity: req.issuer_identity,
            issuer_key: req.issuer_key,
            signature: req.signature,
            recorded_at,
        })
    }

    /// 语义承诺叶子：SHA256(客户端已签名的确定性业务负载)。
    pub fn leaf_hash(&self) -> String {
        let bytes =
            Self::request_signing_payload(&self.payload, &self.issuer_identity, &self.issuer_key);
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    pub fn record_type(&self) -> &'static str {
        self.payload.record_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject_payload() -> CatalogPayload {
        CatalogPayload::Subject(Subject {
            subject_id: "repo:example/project".to_string(),
            subject_type: "repository".to_string(),
            display_name: "Example Project".to_string(),
            source_ref: "https://example.invalid/project".to_string(),
        })
    }

    #[test]
    fn verified_subject_record_has_stable_semantic_leaf() {
        let identity = NodeIdentity::generate("issuer");
        let pk = identity.public_key_base64();
        let payload = subject_payload();
        let signature = identity.sign_base64(&CatalogRecord::request_signing_payload(
            &payload,
            "issuer:example",
            &pk,
        ));
        let record = CatalogRecord::from_verified_request(
            CatalogRecordRequest {
                payload,
                issuer_identity: "issuer:example".to_string(),
                issuer_key: pk,
                signature,
            },
            123,
        )
        .unwrap();
        assert_eq!(record.record_type(), "subject");
        assert!(!record.leaf_hash().is_empty());
        assert_eq!(record.recorded_at, 123);
    }

    #[test]
    fn altered_semantic_payload_fails_signature_verification() {
        let identity = NodeIdentity::generate("issuer");
        let pk = identity.public_key_base64();
        let payload = subject_payload();
        let signature = identity.sign_base64(&CatalogRecord::request_signing_payload(
            &payload,
            "issuer:example",
            &pk,
        ));
        let mut changed = subject_payload();
        if let CatalogPayload::Subject(subject) = &mut changed {
            subject.display_name = "Tampered".to_string();
        }
        assert!(CatalogRecord::from_verified_request(
            CatalogRecordRequest {
                payload: changed,
                issuer_identity: "issuer:example".to_string(),
                issuer_key: pk,
                signature,
            },
            123,
        )
        .is_err());
    }

    #[test]
    fn claim_requires_scope_evidence_and_valid_period() {
        let claim = CatalogPayload::Claim(Claim {
            claim_id: "claim-1".to_string(),
            subject_id: "repo:example/project".to_string(),
            revision_id: String::new(),
            artifact_id: String::new(),
            category: "risk.vulnerability".to_string(),
            status: "confirmed".to_string(),
            evidence_ref: "sha256:report".to_string(),
            observed_at: 10,
            effective_from: Some(20),
            effective_to: Some(10),
            supersedes_claim_id: String::new(),
        });
        assert!(claim.validate().is_err());
    }
}
