//! 最小安全 HTTP 区块同步。
//!
//! 节点发现采用显式注册，区块同步采用受 JWT 保护的拉取/导入接口。
//! Chain::add_block 会逐块校验索引、previous_hash、PoW 和 Merkle root；
//! 本模块不假装提供共识，只在没有共识网络时拒绝冲突区块。

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::core::{Block, Chain};
use crate::error::{DataChainError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub base_url: String,
    #[serde(default)]
    pub last_sync: Option<DateTime<Utc>>,
    // 序列化时隐藏 token;反序列化(如从对端 /peers 交换)时默认 None。
    #[serde(skip_serializing, default)]
    pub auth_token: Option<String>,
}

/// `/api/v1/peers` 响应信封,仅用于 P2P peer 交换时反序列化取 data。
#[derive(Debug, Deserialize)]
struct PeerListEnvelope {
    #[serde(default)]
    data: Option<Vec<PeerInfo>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerRegistration {
    pub peer_id: String,
    pub base_url: String,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    pub peer_id: String,
    pub requested_from: i64,
    pub received: usize,
    pub imported: usize,
    pub local_block_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlocksResponse {
    pub start: i64,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncBlocksRequest {
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncQuery {
    #[serde(default)]
    pub start: i64,
}

pub struct P2PService {
    peers: RwLock<HashMap<String, PeerInfo>>,
    client: Client,
    /// 本节点 ID,用于在注册/发现时跳过自身,避免自环同步。
    self_node_id: String,
}

impl P2PService {
    /// 创建 P2P 服务。未知本节点 ID 时用占位符(不与任何真实 peer 冲突即可)。
    pub fn new() -> Arc<Self> {
        Self::with_node_id("__self__")
    }

    /// 以指定本节点 ID 创建 P2P 服务。
    pub fn with_node_id(self_node_id: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            client: Client::new(),
            self_node_id: self_node_id.into(),
        })
    }

    pub fn register_peer(&self, req: PeerRegistration) -> Result<PeerInfo> {
        if req.peer_id.trim().is_empty() {
            return Err(DataChainError::InvalidBlock(
                "peer_id cannot be empty".to_string(),
            ));
        }
        if req.peer_id == self.self_node_id {
            return Err(DataChainError::InvalidBlock(
                "cannot register self as peer".to_string(),
            ));
        }
        let url = req.base_url.trim_end_matches('/').to_string();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(DataChainError::InvalidBlock(
                "peer URL must use http or https".to_string(),
            ));
        }
        let peer = PeerInfo {
            peer_id: req.peer_id.clone(),
            base_url: url,
            last_sync: None,
            auth_token: req.auth_token,
        };
        self.peers.write().insert(req.peer_id, peer.clone());
        Ok(peer)
    }

    pub fn list_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().values().cloned().collect()
    }

    pub fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        self.peers.read().get(peer_id).cloned()
    }

    pub async fn sync_peer(&self, peer_id: &str, chain: &Arc<Chain>) -> Result<SyncReport> {
        let peer = self
            .get_peer(peer_id)
            .ok_or_else(|| DataChainError::UserNotFound(format!("peer not found: {}", peer_id)))?;
        let start = 0i64;
        let url = format!("{}/api/v1/sync/blocks?start={}", peer.base_url, start);
        let mut request = self.client.get(url);
        if let Some(token) = &peer.auth_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|e| DataChainError::StorageError(format!("peer request failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(DataChainError::StorageError(format!(
                "peer returned HTTP {}",
                response.status()
            )));
        }
        let payload = response
            .json::<SyncBlocksResponse>()
            .await
            .map_err(|e| DataChainError::StorageError(format!("invalid sync response: {}", e)))?;
        let received = payload.blocks.len();
        let before = chain.get_block_count();
        let replaced = chain.replace_chain_if_longer(payload.blocks)?;
        let imported = if replaced {
            chain.get_block_count().saturating_sub(before)
        } else {
            0
        };
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.last_sync = Some(Utc::now());
        }
        Ok(SyncReport {
            peer_id: peer_id.to_string(),
            requested_from: start,
            received,
            imported,
            local_block_count: chain.get_block_count(),
        })
    }

    /// 向所有已注册 peer 主动广播新区块(POST /api/v1/sync/blocks)。
    ///
    /// 挖矿或导入新块后调用,减少对定时拉取的依赖。peer 端 add_block 仍会逐块校验,
    /// 广播失败只记录警告,不影响本地状态(最终一致由定时拉取兜底)。
    pub async fn broadcast_blocks(&self, blocks: Vec<Block>) {
        if blocks.is_empty() {
            return;
        }
        let peers = self.list_peers();
        for peer in peers {
            let url = format!("{}/api/v1/sync/blocks", peer.base_url);
            let mut request = self.client.post(&url).json(&SyncBlocksResponse {
                start: blocks.first().map(|b| b.index).unwrap_or(0),
                blocks: blocks.clone(),
            });
            if let Some(token) = &peer.auth_token {
                request = request.bearer_auth(token);
            }
            match request.send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("已向 {} 广播 {} 个区块", peer.peer_id, blocks.len());
                }
                Ok(resp) => {
                    tracing::warn!("向 {} 广播区块返回 HTTP {}", peer.peer_id, resp.status());
                }
                Err(e) => {
                    tracing::warn!("向 {} 广播区块失败: {}", peer.peer_id, e);
                }
            }
        }
    }

    /// 从已知 peer 交换 peer 列表(受认证保护的 gossip 发现)。
    ///
    /// 仅从已显式注册、已授权的 peer 拉取其 peer 列表并并入本地,不做无认证的全网广播发现。
    /// 新发现的 peer 继承来源 peer 的 auth_token(同一信任域),URL 非法则跳过。
    pub async fn exchange_peers(&self) -> usize {
        let peers = self.list_peers();
        let mut discovered = 0usize;
        for peer in peers {
            let url = format!("{}/api/v1/peers", peer.base_url);
            let mut request = self.client.get(&url);
            if let Some(token) = &peer.auth_token {
                request = request.bearer_auth(token);
            }
            let response = match request.send().await {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    tracing::warn!("从 {} 交换 peer 返回 HTTP {}", peer.peer_id, r.status());
                    continue;
                }
                Err(e) => {
                    tracing::warn!("从 {} 交换 peer 失败: {}", peer.peer_id, e);
                    continue;
                }
            };
            // /api/v1/peers 返回 { success, data: [PeerInfo] } 信封,取 data 字段。
            let envelope = match response.json::<PeerListEnvelope>().await {
                Ok(env) => env,
                Err(e) => {
                    tracing::warn!("解析 {} 的 peer 列表失败: {}", peer.peer_id, e);
                    continue;
                }
            };
            let remote_peers = envelope.data.unwrap_or_default();
            for remote in remote_peers {
                // 跳过自身和已知 peer。
                if remote.peer_id == self.self_node_id || self.get_peer(&remote.peer_id).is_some() {
                    continue;
                }
                let reg = PeerRegistration {
                    peer_id: remote.peer_id.clone(),
                    base_url: remote.base_url.clone(),
                    auth_token: peer.auth_token.clone(),
                };
                if self.register_peer(reg).is_ok() {
                    discovered += 1;
                    tracing::info!("通过 {} 发现新 peer: {}", peer.peer_id, remote.peer_id);
                }
            }
        }
        discovered
    }

    /// 启动定时同步循环。peer 仍需通过注册接口显式加入或经认证 gossip 发现。
    pub fn start_sync_loop(self: Arc<Self>, chain: Arc<Chain>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                // 先交换 peer 发现新节点,再逐个拉取同步。
                let _ = self.exchange_peers().await;
                let peers = self.list_peers();
                for peer in peers {
                    if let Err(error) = self.sync_peer(&peer.peer_id, &chain).await {
                        tracing::warn!("P2P sync with {} failed: {}", peer.peer_id, error);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_peer_validates_url_and_hides_token() {
        let service = P2PService::new();
        let peer = service
            .register_peer(PeerRegistration {
                peer_id: "node-1".to_string(),
                base_url: "http://127.0.0.1:8080/".to_string(),
                auth_token: Some("secret".to_string()),
            })
            .unwrap();
        assert_eq!(peer.base_url, "http://127.0.0.1:8080");
        let json = serde_json::to_string(&peer).unwrap();
        assert!(!json.contains("secret"));
        assert_eq!(service.list_peers().len(), 1);
    }

    #[test]
    fn register_peer_rejects_non_http_url() {
        let service = P2PService::new();
        let result = service.register_peer(PeerRegistration {
            peer_id: "node-1".to_string(),
            base_url: "file:///tmp/node".to_string(),
            auth_token: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn register_peer_is_idempotent_for_discovery() {
        // exchange_peers 依赖 register_peer 对已知 peer 的覆盖幂等。
        let service = P2PService::new();
        for _ in 0..3 {
            service
                .register_peer(PeerRegistration {
                    peer_id: "node-1".to_string(),
                    base_url: "http://127.0.0.1:9000".to_string(),
                    auth_token: Some("t".to_string()),
                })
                .unwrap();
        }
        assert_eq!(service.list_peers().len(), 1);
    }

    #[tokio::test]
    async fn broadcast_without_peers_is_noop() {
        let service = P2PService::new();
        // 无 peer 时广播不应 panic,也无副作用。
        service.broadcast_blocks(Vec::new()).await;
        assert_eq!(service.list_peers().len(), 0);
    }

    #[test]
    fn rejects_registering_self_as_peer() {
        let service = P2PService::with_node_id("node-a");
        let result = service.register_peer(PeerRegistration {
            peer_id: "node-a".to_string(),
            base_url: "http://127.0.0.1:8080".to_string(),
            auth_token: None,
        });
        assert!(result.is_err());
        assert_eq!(service.list_peers().len(), 0);
    }
}
