use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path as FsPath, PathBuf};

use super::{AppState, Event, EventType};
use crate::aggregation::StrategyType;
use crate::auth::{Claims, LoginRequest, RegisterRequest};
use crate::metadata::{CreateMetadataRequest, QueryMetadataRequest};
use crate::p2p::{PeerRegistration, SyncBlocksRequest, SyncBlocksResponse, SyncQuery};

// ==================== 响应结构 ====================

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
}

impl ApiResponse<()> {
    // 放在 impl ApiResponse<()> 而非 impl<T>:返回类型不含 T,置于泛型 impl 中会
    // 导致调用处 T 无法推断(E0283)。固定为 () 后 `ApiResponse::error(..)` 可直接推断。
    pub fn error(msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page: usize,
    pub page_size: usize,
    pub total: usize,
}

// ==================== 健康检查 ====================

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// ==================== 认证处理器 ====================

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.auth_service.register(&req) {
        Ok(user) => {
            // 保存到存储；内存状态不能在持久化失败时对外宣称成功。
            if let Err(e) = state.storage.save_user(&user).await {
                state.auth_service.remove_user(&user.user_id);
                tracing::error!("保存用户失败: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string()))));
            }
            state.event_bus.publish(Event::new(
                EventType::UserRegistered,
                serde_json::to_value(user.to_public()).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(user.to_public()))))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error(e.to_string())))),
    }
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.auth_service.login(&req) {
        Ok(resp) => Ok((StatusCode::OK, Json(ApiResponse::success(resp)))),
        Err(e) => Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::error(e.to_string())))),
    }
}

pub async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.auth_service.get_user_by_id(&claims.sub) {
        Ok(user) => Ok(Json(ApiResponse::success(user.to_public()))),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(ApiResponse::error(e.to_string())))),
    }
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.auth_service.refresh_token(&req.refresh_token) {
        Ok(resp) => Ok(Json(ApiResponse::success(resp))),
        Err(e) => Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::error(e.to_string())))),
    }
}

// ==================== 元数据处理器 ====================

pub async fn create_metadata(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateMetadataRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.metadata_manager.create(&req, &claims.username) {
        Ok(entry) => {
            if let Err(e) = state.storage.save_pending_metadata(&entry).await {
                state.chain.remove_pending_metadata(&entry.data_id);
                tracing::error!("保存待打包元数据失败: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string()))));
            }
            state.event_bus.publish(Event::new(
                EventType::MetadataCreated,
                serde_json::to_value(&entry).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(entry))))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string())))),
    }
}

pub async fn get_metadata(
    State(state): State<AppState>,
    Path(data_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.metadata_manager.get_by_data_id(&data_id) {
        Some(entry) => Ok(Json(ApiResponse::success(entry))),
        None => Err((StatusCode::NOT_FOUND, Json(ApiResponse::error("metadata not found")))),
    }
}

pub async fn query_metadata(
    State(state): State<AppState>,
    Query(mut req): Query<QueryMetadataRequest>,
) -> Json<PaginatedResponse<crate::core::MetadataEntry>> {
    if req.page == 0 {
        req.page = 1;
    }
    if req.page_size == 0 {
        req.page_size = 20;
    }

    let results = state.metadata_manager.query(&req);
    Json(PaginatedResponse {
        total: results.len(),
        data: results,
        page: req.page,
        page_size: req.page_size,
    })
}

// ==================== 区块链处理器 ====================

#[derive(Deserialize)]
pub struct BlocksQuery {
    #[serde(default)]
    pub start: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

pub async fn get_blocks(
    State(state): State<AppState>,
    Query(query): Query<BlocksQuery>,
) -> Json<PaginatedResponse<crate::core::Block>> {
    let blocks = state.chain.get_blocks(query.start, query.limit);
    let total = state.chain.get_block_count();

    Json(PaginatedResponse {
        data: blocks,
        page: query.start / query.limit + 1,
        page_size: query.limit,
        total,
    })
}

pub async fn get_block(
    State(state): State<AppState>,
    Path(index): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.chain.get_block(index) {
        Ok(block) => Ok(Json(ApiResponse::success(block))),
        Err(e) => Err((StatusCode::NOT_FOUND, Json(ApiResponse::error(e.to_string())))),
    }
}

pub async fn get_chain_info(State(state): State<AppState>) -> Json<ApiResponse<crate::core::ChainInfo>> {
    let info = state.chain.get_chain_info();
    Json(ApiResponse::success(info))
}

pub async fn mine_block(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // 检查权限
    if claims.role != "admin" && claims.role != "user" {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::error("permission denied"))));
    }

    match state.chain.mine_block() {
        Ok(block) => {
            // 先持久化区块；失败时恢复内存中的区块和 pending 队列。
            if let Err(e) = state.storage.save_block(&block).await {
                state.chain.rollback_mined_block(&block);
                tracing::error!("保存区块失败: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string()))));
            }

            // 区块落库后再删除对应 pending。两者不是同一 SQLite 事务，删除失败必须显式返回错误。
            for entry in &block.metadata_list {
                if let Err(e) = state.storage.delete_pending_metadata(&entry.data_id).await {
                    tracing::error!("删除已打包元数据失败: {}", e);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string()))));
                }
            }
            state.event_bus.publish(Event::new(
                EventType::BlockMined,
                serde_json::to_value(&block).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(block))))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error(e.to_string())))),
    }
}

#[derive(Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub block_count: usize,
}

pub async fn validate_chain(State(state): State<AppState>) -> Json<ApiResponse<ValidateResponse>> {
    let valid = state.chain.validate_chain();
    let block_count = state.chain.get_block_count();

    state.event_bus.publish(Event::new(
        EventType::ChainValidated,
        serde_json::json!({ "valid": valid, "block_count": block_count }),
    ));
    Json(ApiResponse::success(ValidateResponse { valid, block_count }))
}

// ==================== 版本处理器 ====================

pub async fn get_versions(
    State(state): State<AppState>,
) -> Json<PaginatedResponse<crate::versioning::Version>> {
    let versions = state.version_tracker.get_all_versions();
    let total = versions.len();

    Json(PaginatedResponse {
        data: versions,
        page: 1,
        page_size: total,
        total,
    })
}

pub async fn get_version(
    State(state): State<AppState>,
    Path(version_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.version_tracker.get_version(&version_id) {
        Some(version) => Ok(Json(ApiResponse::success(version))),
        None => Err((StatusCode::NOT_FOUND, Json(ApiResponse::error("version not found")))),
    }
}

const MAX_VERSION_FILE_SIZE: u64 = 50 * 1024 * 1024;

#[derive(Debug)]
pub enum VersionPathValidationError {
    BadRequest(String),
    Forbidden(String),
}

impl VersionPathValidationError {
    fn response(self) -> (StatusCode, Json<ApiResponse<()>>) {
        match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, Json(ApiResponse::error(message))),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, Json(ApiResponse::error(message))),
        }
    }
}

/// 校验版本 API 使用的文件路径，并返回可安全使用的 canonical 路径。
pub fn validate_version_path(file_path: &str) -> Result<PathBuf, VersionPathValidationError> {
    let input = FsPath::new(file_path);
    if file_path.trim().is_empty() {
        return Err(VersionPathValidationError::BadRequest(
            "file_path 不能为空".to_string(),
        ));
    }
    if input.components().any(|component| component == Component::ParentDir) {
        return Err(VersionPathValidationError::BadRequest(
            "file_path 包含不允许的路径穿越组件".to_string(),
        ));
    }

    let configured_root = std::env::var_os("DATACHAIN_VERSION_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        });
    let root = fs::canonicalize(&configured_root).map_err(|error| {
        VersionPathValidationError::Forbidden(format!(
            "版本根目录不可用: {}",
            error
        ))
    })?;
    let candidate = if input.is_absolute() {
        input.to_path_buf()
    } else {
        configured_root.join(input)
    };

    // 检查从目标文件到根路径的每个既存组件，拒绝通过符号链接访问文件。
    let mut component_path = candidate.clone();
    loop {
        match fs::symlink_metadata(&component_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(VersionPathValidationError::Forbidden(
                    "file_path 不允许包含符号链接".to_string(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(VersionPathValidationError::BadRequest(format!(
                    "无法检查 file_path: {}",
                    error
                )));
            }
        }
        if !component_path.pop() {
            break;
        }
    }

    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        VersionPathValidationError::BadRequest(format!("file_path 不可访问: {}", error))
    })?;
    if !canonical.starts_with(&root) {
        return Err(VersionPathValidationError::Forbidden(
            "file_path 必须位于 DATACHAIN_VERSION_ROOT 内".to_string(),
        ));
    }

    let metadata = fs::metadata(&canonical).map_err(|error| {
        VersionPathValidationError::BadRequest(format!("无法读取 file_path 元数据: {}", error))
    })?;
    if metadata.is_dir() {
        return Err(VersionPathValidationError::BadRequest(
            "file_path 必须指向文件，不能是目录".to_string(),
        ));
    }
    if !metadata.is_file() {
        return Err(VersionPathValidationError::BadRequest(
            "file_path 必须指向普通文件".to_string(),
        ));
    }
    if metadata.len() > MAX_VERSION_FILE_SIZE {
        return Err(VersionPathValidationError::BadRequest(format!(
            "file_path 文件大小超过 50 MiB 限制（{} bytes）",
            metadata.len()
        )));
    }

    Ok(canonical)
}

#[derive(Deserialize)]
pub struct TrackVersionRequest {
    pub file_path: String,
    #[serde(default)]
    pub message: String,
}

pub async fn track_version(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<TrackVersionRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let safe_path = validate_version_path(&req.file_path).map_err(VersionPathValidationError::response)?;
    let safe_path = safe_path.to_string_lossy().into_owned();
    let previous_version_id = state
        .version_tracker
        .get_latest_version(&safe_path)
        .map(|version| version.version_id);

    match state.version_tracker.track_file(&safe_path, &claims.username, &req.message) {
        Ok(version) => {
            // 同内容返回既有版本；只有真正的新版本才写入数据库，避免重复 version_id 冲突。
            let is_new_version = previous_version_id.as_deref() != Some(version.version_id.as_str());
            if is_new_version {
                if let Err(e) = state.storage.save_version(&version).await {
                    state.version_tracker.remove_version(&version.version_id);
                    tracing::error!("保存版本失败: {}", e);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string()))));
                }
            }
            state.event_bus.publish(Event::new(
                EventType::VersionTracked,
                serde_json::to_value(&version).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(version))))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string())))),
    }
}

pub async fn get_version_history(
    State(state): State<AppState>,
    Path(file_path): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let safe_path = validate_version_path(&file_path).map_err(VersionPathValidationError::response)?;
    let safe_path = safe_path.to_string_lossy();
    let versions = state.version_tracker.get_version_history(&safe_path);
    let total = versions.len();

    Ok(Json(PaginatedResponse {
        data: versions,
        page: 1,
        page_size: total,
        total,
    }))
}

pub async fn get_version_diff(
    State(state): State<AppState>,
    Path((old_version_id, new_version_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.version_tracker.get_version_diff(&old_version_id, &new_version_id) {
        Ok(diff) => Ok(Json(ApiResponse::success(diff))),
        Err(crate::error::DataChainError::VersionNotFound(version_id)) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!("version not found: {}", version_id))),
        )),
        Err(crate::error::DataChainError::IoError(error))
            if error.kind() == std::io::ErrorKind::NotFound => Err((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("版本内容快照不可用")),
            )),
        Err(crate::error::DataChainError::StorageError(message)) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse::error(message)),
        )),
        Err(error) => {
            tracing::error!("读取版本快照失败: {}", error);
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(error.to_string()))))
        }
    }
}

// ==================== 汇总处理器 ====================

pub async fn get_aggregations(
    State(state): State<AppState>,
) -> Json<PaginatedResponse<crate::aggregation::AggregationSummary>> {
    let aggregations = state.aggregation_engine.get_all_aggregations();
    let total = aggregations.len();

    Json(PaginatedResponse {
        data: aggregations,
        page: 1,
        page_size: total,
        total,
    })
}

pub async fn aggregation_status(State(state): State<AppState>) -> Json<ApiResponse<crate::aggregation::SchedulerStatus>> {
    Json(ApiResponse::success(state.scheduler.get_status()))
}

#[derive(Deserialize)]
pub struct TriggerAggregationRequest {
    #[serde(default = "default_strategy")]
    pub strategy: String,
}

fn default_strategy() -> String {
    "time_based".to_string()
}

pub async fn trigger_aggregation(
    State(state): State<AppState>,
    Json(req): Json<TriggerAggregationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let strategy = match req.strategy.as_str() {
        "time_based" => StrategyType::TimeBased,
        "count_based" => StrategyType::CountBased,
        "recursive" => StrategyType::Recursive,
        _ => StrategyType::Manual,
    };

    match state.aggregation_engine.aggregate(strategy) {
        Some(summary) => {
            if let Err(e) = state.storage.save_aggregation(&summary).await {
                state.aggregation_engine.remove_aggregation(&summary.summary_id);
                tracing::error!("保存聚合结果失败: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string()))));
            }
            state.event_bus.publish(Event::new(
                EventType::AggregationDone,
                serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(summary))))
        }
        None => Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("aggregation failed or no data")))),
    }
}

// ==================== P2P 同步处理器 ====================

pub async fn list_peers(State(state): State<AppState>) -> Json<ApiResponse<Vec<crate::p2p::PeerInfo>>> {
    Json(ApiResponse::success(state.p2p.list_peers()))
}

pub async fn register_peer(
    State(state): State<AppState>,
    Json(req): Json<PeerRegistration>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.p2p.register_peer(req) {
        Ok(peer) => Ok((StatusCode::CREATED, Json(ApiResponse::success(peer)))),
        Err(error) => Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error(error.to_string())))),
    }
}

/// 导出本节点从 start 开始的区块，供其他节点拉取。
pub async fn export_blocks(
    State(state): State<AppState>,
    Query(query): Query<SyncQuery>,
) -> Result<Json<SyncBlocksResponse>, (StatusCode, Json<ApiResponse<()>>)> {
    let start = query.start.max(0) as usize;
    let total = state.chain.get_block_count();
    if start > total {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("sync start is beyond local chain"))));
    }
    Ok(Json(SyncBlocksResponse {
        start: start as i64,
        blocks: state.chain.get_blocks(start, total - start),
    }))
}

/// 导入另一节点提供的区块；Chain::add_block 逐块验证链接、PoW 和 Merkle。
pub async fn import_blocks(
    State(state): State<AppState>,
    Json(req): Json<SyncBlocksRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let mut imported = 0usize;
    for block in req.blocks {
        if let Err(error) = state.chain.add_block(block.clone()) {
            return Err((StatusCode::CONFLICT, Json(ApiResponse::error(format!(
                "block sync rejected after {} blocks: {}", imported, error
            )))));
        }
        if let Err(error) = state.storage.save_block(&block).await {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(error.to_string()))));
        }
        imported += 1;
    }
    Ok(Json(ApiResponse::success(serde_json::json!({ "imported": imported }))))
}

pub async fn sync_peer(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Result<Json<ApiResponse<crate::p2p::SyncReport>>, (StatusCode, Json<ApiResponse<()>>)> {
    match state.p2p.sync_peer(&peer_id, &state.chain).await {
        Ok(report) => Ok(Json(ApiResponse::success(report))),
        Err(error) => Err((StatusCode::BAD_GATEWAY, Json(ApiResponse::error(error.to_string())))),
    }
}

// ==================== 统计处理器 ====================

#[derive(Serialize)]
pub struct StatsResponse {
    pub chain: crate::core::ChainInfo,
    pub metadata: crate::metadata::MetadataStatistics,
    pub versions: crate::versioning::VersionStatistics,
}

pub async fn get_stats(State(state): State<AppState>) -> Json<ApiResponse<StatsResponse>> {
    let chain = state.chain.get_chain_info();
    let metadata = state.metadata_manager.get_statistics();
    let versions = state.version_tracker.get_statistics();

    Json(ApiResponse::success(StatsResponse {
        chain,
        metadata,
        versions,
    }))
}

// ==================== Attestation 处理器 (Task 19) ====================

/// 按哈希查询区块
pub async fn get_block_by_hash(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let blocks = state.chain.get_all_blocks();
    for block in blocks {
        if block.hash == hash {
            return Ok(Json(ApiResponse::success(block)));
        }
    }
    Err((StatusCode::NOT_FOUND, Json(ApiResponse::error(format!("block not found with hash: {}", hash)))))
}

/// 获取内容的 Merkle 证明
#[derive(Serialize)]
pub struct ProofResponse {
    pub found: bool,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_index: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitter_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub async fn get_proof(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Json<ProofResponse> {
    let blocks = state.chain.get_all_blocks();
    
    for block in &blocks {
        // Check attestations array
        for att in &block.attestations {
            if let Some(hash_val) = att.hash_bundle.get("sha256") {
                if hash_val.as_str() == Some(&sha256) {
                    return Json(ProofResponse {
                        found: true,
                        sha256: sha256.clone(),
                        block_index: Some(block.index),
                        block_hash: Some(block.hash.clone()),
                        merkle_root: Some(block.merkle_root.clone()),
                        submitter_key: Some(att.submitter_key.clone()),
                        reason: None,
                    });
                }
            }
        }
        // Check metadata tags
        for meta in &block.metadata_list {
            if meta.tags.contains(&sha256) {
                return Json(ProofResponse {
                    found: true,
                    sha256: sha256.clone(),
                    block_index: Some(block.index),
                    block_hash: Some(block.hash.clone()),
                    merkle_root: Some(block.merkle_root.clone()),
                    submitter_key: None,
                    reason: None,
                });
            }
        }
    }

    Json(ProofResponse {
        found: false,
        sha256,
        block_index: None,
        block_hash: None,
        merkle_root: None,
        submitter_key: None,
        reason: Some("content hash not found in any block attestation".to_string()),
    })
}

#[cfg(test)]
mod version_path_tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_before_filesystem_access() {
        let result = validate_version_path("../outside.txt");
        assert!(matches!(result, Err(VersionPathValidationError::BadRequest(_))));
    }

    #[test]
    fn rejects_directories_as_version_files() {
        let root = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(root).unwrap();
        let result = validate_version_path(directory.path().to_str().unwrap());
        assert!(matches!(result, Err(VersionPathValidationError::BadRequest(_))));
    }

    #[test]
    fn accepts_a_regular_file_under_the_default_root() {
        let root = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(&root).unwrap();
        let file = directory.path().join("safe.txt");
        std::fs::write(&file, b"safe").unwrap();

        let validated = validate_version_path(file.to_str().unwrap()).unwrap();
        assert_eq!(validated, std::fs::canonicalize(file).unwrap());
    }
}
