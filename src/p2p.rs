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
    pub last_sync: Option<DateTime<Utc>>,
    #[serde(skip_serializing)]
    pub auth_token: Option<String>,
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
}

impl P2PService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            client: Client::new(),
        })
    }

    pub fn register_peer(&self, req: PeerRegistration) -> Result<PeerInfo> {
        if req.peer_id.trim().is_empty() {
            return Err(DataChainError::InvalidBlock("peer_id cannot be empty".to_string()));
        }
        let url = req.base_url.trim_end_matches('/').to_string();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(DataChainError::InvalidBlock("peer URL must use http or https".to_string()));
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

    /// 启动定时同步循环。peer 仍需通过注册接口显式加入，避免无认证自动发现。
    pub fn start_sync_loop(self: Arc<Self>, chain: Arc<Chain>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
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
}
