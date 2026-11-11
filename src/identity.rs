//! 链上身份与密钥交易(backlog L1,身份最小版)。
//!
//! 节点/用户可在链上登记公钥(register)与撤销公钥(revoke),每条交易由 ed25519 签名
//! 保证真实性,随区块打包后进入 merkle_root 受哈希/PoW 保护(见 Block::calculate_merkle_root)。
//! 「当前有效密钥集」不单独建表,而是由区块里的 key_transactions 重放得出(权威源=链),
//! 与 DataChain「数据权威源在链、查询为派生投影」的一贯取舍一致。
//!
//! 可信根不靠本链自证:身份快照(identity_snapshot_hash)会随跨链锚定发布到外部链,
//! 由外链的去中心化不可篡改性为「某公钥在某高度已注册/已撤销」背书(见 L2/L3)。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::{Block, KeyTransactionEntry};
use crate::error::{DataChainError, Result};
use crate::node_signing::NodeIdentity;

/// 密钥交易类型。
pub const TX_REGISTER: &str = "register";
pub const TX_REVOKE: &str = "revoke";

/// 提交密钥交易的请求体。签名针对 `KeyTransactionEntry::signing_payload()`。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyTransactionRequest {
    /// register / revoke。
    pub tx_type: String,
    /// 目标公钥(base64)。
    pub target_key: String,
    /// 角色标签(可选,如 node/admin/user)。
    #[serde(default)]
    pub role: String,
    /// 可读标签(可选)。
    #[serde(default)]
    pub label: String,
    /// 发起方公钥(base64):register 通常自签(signed_by==target_key),
    /// revoke 可由 target_key 自身或管理密钥签。
    pub signed_by: String,
    /// 对规范化负载的 ed25519 签名(base64)。
    pub signature: String,
    /// 可选原因(撤销时常用)。
    #[serde(default)]
    pub reason: String,
}

/// 当前有效密钥集中的一项。
#[derive(Debug, Clone, Serialize)]
pub struct KeyRecord {
    pub public_key: String,
    pub role: String,
    pub label: String,
    pub registered_at: i64,
    pub status: String,
}

/// 校验并构造一条待打包密钥交易。
///
/// 规则(最小版):
/// - tx_type 必须是 register / revoke;
/// - target_key / signed_by 必须是合法 base64 ed25519 公钥;
/// - 签名必须对 `signing_payload()` 由 signed_by 公钥验证通过;
/// - register 要求自签(signed_by == target_key),证明持有对应私钥。
///   revoke 允许 signed_by 为 target_key 自身或其他密钥(管理密钥策略留待后续细化)。
pub fn build_verified_key_transaction(
    req: &KeyTransactionRequest,
    now_ts: i64,
) -> Result<KeyTransactionEntry> {
    if req.tx_type != TX_REGISTER && req.tx_type != TX_REVOKE {
        return Err(DataChainError::InvalidBlock(format!(
            "unknown key transaction type: {}",
            req.tx_type
        )));
    }
    if req.target_key.trim().is_empty() || req.signed_by.trim().is_empty() {
        return Err(DataChainError::InvalidBlock(
            "target_key/signed_by must not be empty".to_string(),
        ));
    }
    if req.tx_type == TX_REGISTER && req.signed_by != req.target_key {
        return Err(DataChainError::InvalidBlock(
            "register must be self-signed (signed_by == target_key)".to_string(),
        ));
    }

    let entry = KeyTransactionEntry {
        tx_type: req.tx_type.clone(),
        target_key: req.target_key.clone(),
        role: req.role.clone(),
        label: req.label.clone(),
        signed_by: req.signed_by.clone(),
        signature: req.signature.clone(),
        timestamp: now_ts,
        reason: req.reason.clone(),
    };

    // 用 signed_by 公钥验签规范化负载;验签失败/公钥非法都拒绝。
    let ok = NodeIdentity::verify_base64(&req.signed_by, &entry.signing_payload(), &req.signature)?;
    if !ok {
        return Err(DataChainError::InvalidToken);
    }
    Ok(entry)
}

/// 由区块序列重放出当前有效密钥集。
///
/// 按区块顺序回放:register 加入/更新为 active;revoke 标记为 revoked 并从有效集移除。
/// 返回仅含当前 active 的记录,按公钥稳定排序(BTreeMap),便于计算确定性快照哈希。
pub fn replay_key_set(blocks: &[Block]) -> BTreeMap<String, KeyRecord> {
    let mut set: BTreeMap<String, KeyRecord> = BTreeMap::new();
    for block in blocks {
        for tx in &block.key_transactions {
            match tx.tx_type.as_str() {
                TX_REGISTER => {
                    set.insert(
                        tx.target_key.clone(),
                        KeyRecord {
                            public_key: tx.target_key.clone(),
                            role: tx.role.clone(),
                            label: tx.label.clone(),
                            registered_at: tx.timestamp,
                            status: "active".to_string(),
                        },
                    );
                }
                TX_REVOKE => {
                    set.remove(&tx.target_key);
                }
                _ => {}
            }
        }
    }
    set
}

/// 计算当前有效密钥集的确定性快照哈希(identity_snapshot_hash)。
///
/// 对按公钥排序的有效集做规范化拼接后 SHA256。空集返回空串。
/// 该哈希写入区块头,并随跨链锚定发布到外链,作为身份状态的可锚定承诺。
pub fn compute_identity_snapshot_hash(key_set: &BTreeMap<String, KeyRecord>) -> String {
    if key_set.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    for (pk, rec) in key_set {
        hasher.update(pk.as_bytes());
        hasher.update(b"|");
        hasher.update(rec.role.as_bytes());
        hasher.update(b"|");
        hasher.update(rec.registered_at.to_string().as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_request(tx_type: &str, id: &NodeIdentity, role: &str) -> KeyTransactionRequest {
        let pk = id.public_key_base64();
        let mut req = KeyTransactionRequest {
            tx_type: tx_type.to_string(),
            target_key: pk.clone(),
            role: role.to_string(),
            label: "n".to_string(),
            signed_by: pk,
            signature: String::new(),
            reason: String::new(),
        };
        // 用与 build_verified_key_transaction 相同的规范化负载签名。
        let probe = KeyTransactionEntry {
            tx_type: req.tx_type.clone(),
            target_key: req.target_key.clone(),
            role: req.role.clone(),
            label: req.label.clone(),
            signed_by: req.signed_by.clone(),
            signature: String::new(),
            timestamp: 0,
            reason: String::new(),
        };
        req.signature = id.sign_base64(&probe.signing_payload());
        req
    }

    #[test]
    fn register_requires_valid_self_signature() {
        let id = NodeIdentity::generate("n1");
        let req = signed_request(TX_REGISTER, &id, "node");
        // timestamp 不参与签名,故服务端用任意 now_ts(这里 123)都能验签通过。
        let entry = build_verified_key_transaction(&req, 123).unwrap();
        assert_eq!(entry.tx_type, TX_REGISTER);
        assert_eq!(entry.timestamp, 123, "服务端应独立盖 timestamp");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let id = NodeIdentity::generate("n1");
        let mut req = signed_request(TX_REGISTER, &id, "node");
        req.signature = "AAAA".to_string();
        assert!(build_verified_key_transaction(&req, 0).is_err());
    }

    #[test]
    fn register_must_be_self_signed() {
        let id = NodeIdentity::generate("n1");
        let other = NodeIdentity::generate("n2");
        let mut req = signed_request(TX_REGISTER, &id, "node");
        req.signed_by = other.public_key_base64();
        assert!(build_verified_key_transaction(&req, 0).is_err());
    }

    #[test]
    fn replay_register_then_revoke() {
        let id = NodeIdentity::generate("n1");
        let pk = id.public_key_base64();
        let reg =
            build_verified_key_transaction(&signed_request(TX_REGISTER, &id, "node"), 0).unwrap();

        let mut b1 = Block::new(1, "0".repeat(64), 1);
        b1.key_transactions.push(reg);
        let set = replay_key_set(std::slice::from_ref(&b1));
        assert!(set.contains_key(&pk));
        assert_eq!(set.get(&pk).unwrap().status, "active");
        let snap1 = compute_identity_snapshot_hash(&set);
        assert!(!snap1.is_empty());

        // revoke 自签。
        let mut revoke_req = signed_request(TX_REVOKE, &id, "node");
        // 重新签名 revoke 负载(tx_type 变了)。
        let probe = KeyTransactionEntry {
            tx_type: TX_REVOKE.to_string(),
            target_key: pk.clone(),
            role: "node".to_string(),
            label: "n".to_string(),
            signed_by: pk.clone(),
            signature: String::new(),
            timestamp: 0,
            reason: String::new(),
        };
        revoke_req.signature = id.sign_base64(&probe.signing_payload());
        let rev = build_verified_key_transaction(&revoke_req, 0).unwrap();

        let mut b2 = Block::new(2, b1.hash.clone(), 1);
        b2.key_transactions.push(rev);
        let set2 = replay_key_set(&[b1, b2]);
        assert!(!set2.contains_key(&pk), "revoke 后应从有效集移除");
        assert!(compute_identity_snapshot_hash(&set2).is_empty());
    }
}
