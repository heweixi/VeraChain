use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// 简化的 HTTP 服务器（实际用 actix-web/axum）
// 这里展示核心数据结构和 API 逻辑

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub id: String,
    pub sender: String,
    pub receiver: String,
    pub amount: f64,
    pub fee: f64,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Peer {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub status: String,
    pub last_seen: u64,
}

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub pending_txs: Vec<Transaction>,
    pub peers: HashMap<String, Peer>,
    pub difficulty: u32,
}

impl Blockchain {
    pub fn new() -> Self {
        let genesis = Block {
            index: 0,
            timestamp: now(),
            previous_hash: "0".repeat(64),
            hash: "genesis_hash".to_string(),
            transactions: vec![],
            nonce: 0,
        };
        Blockchain {
            chain: vec![genesis],
            pending_txs: vec![],
            peers: HashMap::new(),
            difficulty: 4,
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> bool {
        if tx.amount <= 0.0 { return false; }
        self.pending_txs.push(tx);
        true
    }

    pub fn mine_block(&mut self, miner: &str) -> Option<Block> {
        if self.pending_txs.is_empty() { return None; }
        let prev = self.chain.last().unwrap();
        let block = Block {
            index: prev.index + 1,
            timestamp: now(),
            previous_hash: prev.hash.clone(),
            hash: format!("block_{}", prev.index + 1),
            transactions: self.pending_txs.drain(..).collect(),
            nonce: 0,
        };
        self.chain.push(block.clone());
        Some(block)
    }

    pub fn get_block(&self, index: u64) -> Option<&Block> {
        self.chain.get(index as usize)
    }

    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.insert(peer.id.clone(), peer);
    }

    pub fn get_peers(&self) -> Vec<&Peer> {
        self.peers.values().collect()
    }

    pub fn chain_length(&self) -> u64 {
        self.chain.len() as u64
    }

    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            if self.chain[i].previous_hash != self.chain[i - 1].hash {
                return false;
            }
        }
        true
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// API 路由 (用 actix-web 实现)
// GET  /health
// GET  /api/blocks
// GET  /api/blocks/:index
// POST /api/transactions
// POST /api/mine
// GET  /api/peers
// POST /api/peers

fn main() {
    println!("DataChain Rust v1.0.0");
    println!("Starting on :8080...");

    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    
    // 实际启动 HTTP server
    // actix_web::HttpServer::new(move || { ... })
    
    println!("Blockchain initialized: {} blocks", blockchain.lock().unwrap().chain_length());
    println!("Endpoints: /health, /api/blocks, /api/transactions, /api/peers");
}
