use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use super::AppState;
use crate::aggregation::StrategyType;
use crate::auth::{Claims, LoginRequest, RegisterRequest};
use crate::metadata::{CreateMetadataRequest, QueryMetadataRequest};

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
            // 保存到存储
            if let Err(e) = state.storage.save_user(&user).await {
                tracing::error!("保存用户失败: {}", e);
            }
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
        Ok(entry) => Ok((StatusCode::CREATED, Json(ApiResponse::success(entry)))),
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
            // 保存到存储
            if let Err(e) = state.storage.save_block(&block).await {
                tracing::error!("保存区块失败: {}", e);
            }
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
    match state.version_tracker.track_file(&req.file_path, &claims.username, &req.message) {
        Ok(version) => {
            // 保存到存储
            if let Err(e) = state.storage.save_version(&version).await {
                tracing::error!("保存版本失败: {}", e);
            }
            Ok((StatusCode::CREATED, Json(ApiResponse::success(version))))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(e.to_string())))),
    }
}

pub async fn get_version_history(
    State(state): State<AppState>,
    Path(file_path): Path<String>,
) -> Json<PaginatedResponse<crate::versioning::Version>> {
    let versions = state.version_tracker.get_version_history(&file_path);
    let total = versions.len();

    Json(PaginatedResponse {
        data: versions,
        page: 1,
        page_size: total,
        total,
    })
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
        Some(summary) => Ok((StatusCode::CREATED, Json(ApiResponse::success(summary)))),
        None => Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("aggregation failed or no data")))),
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
