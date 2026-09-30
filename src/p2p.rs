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
        let start = chain.get_block_count() as i64;
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
        let mut imported = 0;
        for block in payload.blocks {
            chain.add_block(block)?;
            imported += 1;
        }
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
}
