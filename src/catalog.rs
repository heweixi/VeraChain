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

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{ClaimPolicyConfig, TrustedIssuerConfig};
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

/// 查询投影中附带区块高度的目录记录。区块高度用于对相同权重声明给出可解释的时间顺序。
#[derive(Debug, Clone, Serialize)]
pub struct CatalogRecordAtBlock {
    pub record: CatalogRecord,
    pub block_index: i64,
}

/// 一条被当前信任策略接受的有效 Claim。
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedClaim {
    pub claim: Claim,
    pub record_id: String,
    pub issuer_identity: String,
    pub issuer_key: String,
    pub trust_weight: u32,
    pub block_index: i64,
}

/// 同一对象范围、同一分类出现同权重但不同状态的可信 Claim 时，不强行裁决。
#[derive(Debug, Clone, Serialize)]
pub struct ClaimConflict {
    pub subject_id: String,
    pub revision_id: String,
    pub artifact_id: String,
    pub category: String,
    pub candidates: Vec<ResolvedClaim>,
}

/// 指定时间点的有效 Claim 解析结果。
#[derive(Debug, Clone, Serialize)]
pub struct ClaimResolution {
    pub as_of: i64,
    pub effective_claims: Vec<ResolvedClaim>,
    pub conflicts: Vec<ClaimConflict>,
}

/// 配置驱动的 Claim resolver。
///
/// 它不删除或改写历史 Claim，而是按可信签发者、分类授权、权重、有效时间与覆盖关系得到
/// 当前有效结论。未配置可信签发者时，原始历史仍可查询，但不会产生有效结论（fail-closed）。
#[derive(Debug, Clone)]
pub struct ClaimResolver {
    policy: ClaimPolicyConfig,
}

impl ClaimResolver {
    pub fn new(policy: ClaimPolicyConfig) -> Self {
        Self { policy }
    }

    fn trusted_issuer<'a>(
        &'a self,
        record: &CatalogRecord,
        category: &str,
    ) -> Option<&'a TrustedIssuerConfig> {
        self.policy.trusted_issuers.iter().find(|issuer| {
            issuer.weight >= self.policy.min_weight
                && issuer.issuer_identity == record.issuer_identity
                && issuer.issuer_key == record.issuer_key
                && category_allowed(&issuer.categories, category)
        })
    }

    /// 解析指定时点（Unix 秒）的有效 Claim。
    pub fn resolve(&self, records: Vec<CatalogRecordAtBlock>, as_of: i64) -> ClaimResolution {
        // 首先筛选“签发者可信且分类获授权且在生效窗口内”的声明。
        let mut candidates = Vec::<ResolvedClaim>::new();
        for item in records {
            let CatalogPayload::Claim(claim) = &item.record.payload else {
                continue;
            };
            let Some(issuer) = self.trusted_issuer(&item.record, &claim.category) else {
                continue;
            };
            let from = claim.effective_from.unwrap_or(claim.observed_at);
            if from > as_of || claim.effective_to.is_some_and(|to| to < as_of) {
                continue;
            }
            candidates.push(ResolvedClaim {
                claim: claim.clone(),
                record_id: item.record.record_id,
                issuer_identity: item.record.issuer_identity,
                issuer_key: item.record.issuer_key,
                trust_weight: issuer.weight,
                block_index: item.block_index,
            });
        }

        // 一个可信后续声明显式 supersedes 旧声明时，旧声明不再参与当前结论。
        let superseded: HashSet<String> = candidates
            .iter()
            .filter_map(|item| {
                (!item.claim.supersedes_claim_id.is_empty())
                    .then_some(item.claim.supersedes_claim_id.clone())
            })
            .collect();
        candidates.retain(|item| {
            !superseded.contains(&item.claim.claim_id)
                && item.claim.status != "withdrawn"
                && item.claim.status != "superseded"
        });

        let mut grouped: BTreeMap<(String, String, String, String), Vec<ResolvedClaim>> =
            BTreeMap::new();
        for item in candidates {
            grouped
                .entry((
                    item.claim.subject_id.clone(),
                    item.claim.revision_id.clone(),
                    item.claim.artifact_id.clone(),
                    item.claim.category.clone(),
                ))
                .or_default()
                .push(item);
        }

        let mut effective_claims = Vec::new();
        let mut conflicts = Vec::new();
        for ((subject_id, revision_id, artifact_id, category), mut group) in grouped {
            let max_weight = group
                .iter()
                .map(|item| item.trust_weight)
                .max()
                .unwrap_or(0);
            group.retain(|item| item.trust_weight == max_weight);
            let statuses: HashSet<String> =
                group.iter().map(|item| item.claim.status.clone()).collect();
            if statuses.len() > 1 {
                // 同权重认证者给出不同状态，公开保留冲突，不伪造一个单一结论。
                conflicts.push(ClaimConflict {
                    subject_id,
                    revision_id,
                    artifact_id,
                    category,
                    candidates: group,
                });
            } else {
                // 同一状态可由多个等权可信认证者共同支持，全部保留为有效证据。
                group.sort_by_key(|item| (item.block_index, item.record_id.clone()));
                effective_claims.extend(group);
            }
        }
        ClaimResolution {
            as_of,
            effective_claims,
            conflicts,
        }
    }
}

fn category_allowed(allowed: &[String], category: &str) -> bool {
    allowed.is_empty()
        || allowed.iter().any(|rule| {
            rule == category
                || rule
                    .strip_suffix(".*")
                    .is_some_and(|prefix| category.starts_with(&format!("{}.", prefix)))
        })
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

#[cfg(test)]
mod resolver_tests {
    use super::*;

    fn claim_record(
        claim_id: &str,
        status: &str,
        supersedes: &str,
        issuer_identity: &str,
        issuer_key: &str,
        recorded_at: i64,
    ) -> CatalogRecordAtBlock {
        CatalogRecordAtBlock {
            record: CatalogRecord {
                record_id: format!("record-{}", claim_id),
                payload: CatalogPayload::Claim(Claim {
                    claim_id: claim_id.to_string(),
                    subject_id: "repo-example".to_string(),
                    revision_id: "rev-1".to_string(),
                    artifact_id: String::new(),
                    category: "risk.vulnerability".to_string(),
                    status: status.to_string(),
                    evidence_ref: format!("sha256:{}", claim_id),
                    observed_at: 100,
                    effective_from: Some(100),
                    effective_to: None,
                    supersedes_claim_id: supersedes.to_string(),
                }),
                issuer_identity: issuer_identity.to_string(),
                issuer_key: issuer_key.to_string(),
                signature: String::new(),
                recorded_at,
            },
            block_index: recorded_at,
        }
    }

    fn resolver() -> ClaimResolver {
        ClaimResolver::new(ClaimPolicyConfig {
            min_weight: 1,
            trusted_issuers: vec![TrustedIssuerConfig {
                issuer_identity: "security-lab".to_string(),
                issuer_key: "key-security-lab".to_string(),
                weight: 10,
                categories: vec!["risk.*".to_string()],
            }],
        })
    }

    #[test]
    fn resolver_honors_trust_scope_and_superseding_history() {
        let old = claim_record(
            "old-risk",
            "confirmed",
            "",
            "security-lab",
            "key-security-lab",
            1,
        );
        let replacement = claim_record(
            "fixed-risk",
            "resolved",
            "old-risk",
            "security-lab",
            "key-security-lab",
            2,
        );
        let untrusted = claim_record("untrusted-risk", "confirmed", "", "random", "key-random", 3);
        let result = resolver().resolve(vec![old, replacement, untrusted], 200);
        assert!(result.conflicts.is_empty());
        assert_eq!(result.effective_claims.len(), 1);
        assert_eq!(result.effective_claims[0].claim.claim_id, "fixed-risk");
        assert_eq!(result.effective_claims[0].claim.status, "resolved");
    }

    #[test]
    fn resolver_exposes_equal_weight_status_conflicts() {
        let confirmed = claim_record(
            "risk-confirmed",
            "confirmed",
            "",
            "security-lab",
            "key-security-lab",
            1,
        );
        let disputed = claim_record(
            "risk-disputed",
            "disputed",
            "",
            "security-lab",
            "key-security-lab",
            2,
        );
        let result = resolver().resolve(vec![confirmed, disputed], 200);
        assert!(result.effective_claims.is_empty());
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].candidates.len(), 2);
    }

    #[test]
    fn resolver_fails_closed_without_trusted_issuer() {
        let record = claim_record(
            "risk",
            "confirmed",
            "",
            "security-lab",
            "key-security-lab",
            1,
        );
        let result = ClaimResolver::new(ClaimPolicyConfig::default()).resolve(vec![record], 200);
        assert!(result.effective_claims.is_empty());
        assert!(result.conflicts.is_empty());
    }
}
