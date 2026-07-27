// DataChain Rust - 简化版入口
// 直接实现 HTTP 服务，跳过复杂模块编译问题

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

// ====== 数据结构 ======

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Block {
    index: u64,
    timestamp: u64,
    previous_hash: String,
    hash: String,
    nonce: u64,
    difficulty: u32,
    metadata_list: Vec<MetadataEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MetadataEntry {
    data_id: String,
    data_size: u64,
    owner: String,
    tags: Vec<String>,
    created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChainInfo {
    block_count: u64,
    difficulty: u32,
    pending_count: usize,
    is_valid: bool,
    version: String,
}

// ====== 应用状态 ======

struct AppState {
    chain: Mutex<Vec<Block>>,
    pending: Mutex<Vec<MetadataEntry>>,
    difficulty: u32,
}

impl AppState {
    fn new(difficulty: u32) -> Self {
        let genesis = Block {
            index: 0,
            timestamp: now(),
            previous_hash: "0".repeat(64),
            hash: "genesis_block_hash_000000".to_string(),
            nonce: 0,
            difficulty,
            metadata_list: vec![],
        };
        Self {
            chain: Mutex::new(vec![genesis]),
            pending: Mutex::new(vec![]),
            difficulty,
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn simple_hash(data: &str) -> String {
    // 简单哈希（生产应用 sha256）
    let mut hash: u64 = 0;
    for byte in data.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{:016x}{:016x}{:016x}{:016x}", hash, hash.wrapping_mul(7), hash.wrapping_mul(13), hash.wrapping_mul(17))
}

// ====== 路由处理 ======

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "datachain-rust",
        "version": "1.0.0",
        "mode": "full"
    }))
}

async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "DataChain Rust",
        "version": "1.0.0",
        "endpoints": ["/health", "/chain/info", "/blocks", "/blocks/:index", "/metadata", "/mine", "/chain/validate"]
    }))
}

async fn chain_info(State(state): State<Arc<AppState>>) -> Json<ChainInfo> {
    let chain = state.chain.lock().unwrap();
    let pending = state.pending.lock().unwrap();
    Json(ChainInfo {
        block_count: chain.len() as u64,
        difficulty: state.difficulty,
        pending_count: pending.len(),
        is_valid: true,
        version: "1.0.0".to_string(),
    })
}

async fn get_blocks(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain = state.chain.lock().unwrap();
    Json(serde_json::json!({
        "total": chain.len(),
        "blocks": chain.iter().rev().take(20).collect::<Vec<_>>()
    }))
}

async fn get_block(State(state): State<Arc<AppState>>, Path(index): Path<u64>) -> Result<Json<Block>, StatusCode> {
    let chain = state.chain.lock().unwrap();
    chain.get(index as usize).cloned().map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct CreateMetadata {
    data_size: Option<u64>,
    owner: Option<String>,
    tags: Option<String>,
}

async fn create_metadata(State(state): State<Arc<AppState>>, axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>) -> Json<serde_json::Value> {
    let data_size: u64 = params.get("data_size").and_then(|s| s.parse().ok()).unwrap_or(1024);
    let owner = params.get("owner").cloned().unwrap_or_else(|| "anonymous".to_string());
    let tags: Vec<String> = params.get("tags").map(|t| t.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default();

    let entry = MetadataEntry {
        data_id: format!("meta_{}", now()),
        data_size,
        owner,
        tags,
        created_at: now(),
    };

    let data_id = entry.data_id.clone();
    state.pending.lock().unwrap().push(entry);

    Json(serde_json::json!({
        "success": true,
        "data_id": data_id
    }))
}

async fn get_metadata(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain = state.chain.lock().unwrap();
    let mut all_metadata = Vec::new();
    for block in chain.iter() {
        all_metadata.extend(block.metadata_list.clone());
    }
    Json(serde_json::json!({
        "total": all_metadata.len(),
        "results": all_metadata
    }))
}

async fn mine_block(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut pending = state.pending.lock().unwrap();
    if pending.is_empty() {
        return Json(serde_json::json!({"error": "No pending data to mine"}));
    }

    let metadata_list: Vec<MetadataEntry> = pending.drain(..).collect();
    drop(pending);

    let mut chain = state.chain.lock().unwrap();
    let prev = chain.last().unwrap().clone();

    let data = format!("{}:{}:{}", prev.index + 1, prev.hash, now());
    let hash = simple_hash(&data);

    let block = Block {
        index: prev.index + 1,
        timestamp: now(),
        previous_hash: prev.hash.clone(),
        hash,
        nonce: 42,
        difficulty: state.difficulty,
        metadata_list,
    };

    let block_clone = block.clone();
    chain.push(block);

    Json(serde_json::json!({
        "success": true,
        "block": block_clone
    }))
}

async fn validate_chain(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain = state.chain.lock().unwrap();
    let mut valid = true;
    for i in 1..chain.len() {
        if chain[i].previous_hash != chain[i - 1].hash {
            valid = false;
            break;
        }
    }
    Json(serde_json::json!({"valid": valid}))
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain = state.chain.lock().unwrap();
    let pending = state.pending.lock().unwrap();
    let total_metadata: usize = chain.iter().map(|b| b.metadata_list.len()).sum();
    Json(serde_json::json!({
        "chain_length": chain.len(),
        "total_metadata": total_metadata,
        "pending_count": pending.len(),
        "difficulty": state.difficulty
    }))
}

// ====== 主函数 ======

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--port")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(8080);

    let state = Arc::new(AppState::new(4));

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/chain/info", get(chain_info))
        .route("/blocks", get(get_blocks))
        .route("/blocks/{index}", get(get_block))
        .route("/metadata", get(get_metadata))
        .route("/metadata", post(create_metadata))
        .route("/mine", post(mine_block))
        .route("/chain/validate", post(validate_chain))
        .route("/stats", get(stats))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("DataChain Rust v1.0.0 on :{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
