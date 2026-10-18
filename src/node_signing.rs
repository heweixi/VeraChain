//! 节点身份与 ed25519 签名。
//!
//! 每个 DataChain 节点持有一个 ed25519 密钥对，用于对跨链锚定（ChainAnchor）
//! 和回执（AnchorReceipt）签名。目标链或审计方可凭节点公钥独立验签，
//! 无需信任传输通道。密钥以 base64 持久化，便于写入配置或数据库。

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{DataChainError, Result};

/// 节点签名身份：封装 ed25519 密钥对。
#[derive(Clone)]
pub struct NodeIdentity {
    node_id: String,
    signing_key: SigningKey,
}

impl NodeIdentity {
    /// 生成随机节点身份。
    pub fn generate(node_id: impl Into<String>) -> Self {
        let mut csprng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self {
            node_id: node_id.into(),
            signing_key,
        }
    }

    /// 从 base64 私钥种子恢复身份（32 字节 seed）。
    pub fn from_secret_base64(node_id: impl Into<String>, secret_b64: &str) -> Result<Self> {
        let bytes = B64
            .decode(secret_b64.trim())
            .map_err(|e| DataChainError::ConfigError(format!("无效的节点私钥 base64: {}", e)))?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| DataChainError::ConfigError("节点私钥种子必须为 32 字节".to_string()))?;
        Ok(Self {
            node_id: node_id.into(),
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// 节点 ID。
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// base64 私钥种子（用于持久化，注意保密）。
    pub fn secret_base64(&self) -> String {
        B64.encode(self.signing_key.to_bytes())
    }

    /// base64 公钥，可公开分发给目标链/审计方。
    pub fn public_key_base64(&self) -> String {
        B64.encode(self.signing_key.verifying_key().to_bytes())
    }

    /// 对任意字节签名，返回 base64 签名。
    pub fn sign_base64(&self, message: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(message);
        B64.encode(sig.to_bytes())
    }

    /// 用给定 base64 公钥验证 base64 签名。
    pub fn verify_base64(
        public_key_b64: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<bool> {
        let pk_bytes = B64
            .decode(public_key_b64.trim())
            .map_err(|e| DataChainError::ConfigError(format!("无效的公钥 base64: {}", e)))?;
        let pk_arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DataChainError::ConfigError("公钥必须为 32 字节".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| DataChainError::ConfigError(format!("无效的公钥: {}", e)))?;

        let sig_bytes = B64
            .decode(signature_b64.trim())
            .map_err(|e| DataChainError::ConfigError(format!("无效的签名 base64: {}", e)))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DataChainError::ConfigError("签名必须为 64 字节".to_string()))?;
        let signature = Signature::from_bytes(&sig_arr);

        Ok(verifying_key.verify(message, &signature).is_ok())
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("public_key", &self.public_key_base64())
            .finish()
    }
}

/// 节点公开身份，可序列化分发（不含私钥）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePublicIdentity {
    pub node_id: String,
    pub public_key: String,
}

impl From<&NodeIdentity> for NodePublicIdentity {
    fn from(identity: &NodeIdentity) -> Self {
        Self {
            node_id: identity.node_id().to_string(),
            public_key: identity.public_key_base64(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let identity = NodeIdentity::generate("node-a");
        let msg = b"cross-chain-anchor-payload";
        let sig = identity.sign_base64(msg);
        let pk = identity.public_key_base64();
        assert!(NodeIdentity::verify_base64(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let identity = NodeIdentity::generate("node-a");
        let sig = identity.sign_base64(b"original");
        let pk = identity.public_key_base64();
        assert!(!NodeIdentity::verify_base64(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn secret_roundtrip_preserves_key() {
        let identity = NodeIdentity::generate("node-a");
        let secret = identity.secret_base64();
        let restored = NodeIdentity::from_secret_base64("node-a", &secret).unwrap();
        assert_eq!(identity.public_key_base64(), restored.public_key_base64());
    }
}
