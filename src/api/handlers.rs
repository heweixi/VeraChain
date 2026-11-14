use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path as FsPath, PathBuf};

use super::{AppState, Event, EventType};
use crate::aggregation::StrategyType;
use crate::auth::{ChangePasswordRequest, Claims, LoginContext, LoginRequest, RegisterRequest};
use crate::core::{metadata_leaf_hash, MerkleTree};
use crate::metadata::{CreateMetadataRequest, QueryMetadataRequest};
use crate::net::ClientIp;
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
    match state
        .auth_service
        .register_validated(&req, crate::auth::Role::User)
        .await
    {
        Ok(user) => {
            // register_validated 在三把写锁内复检唯一性,成功即本请求独占该 user_id,
            // 因此下面失败回滚只会移除本请求插入的用户。
            // 保存到存储；内存状态不能在持久化失败时对外宣称成功。
            if let Err(e) = state.storage.save_user(&user).await {
                state.auth_service.remove_user(&user.user_id);
                tracing::error!("保存用户失败: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error("internal error")),
                ));
            }
            state.event_bus.publish(Event::new(
                EventType::UserRegistered,
                serde_json::to_value(user.to_public()).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((
                StatusCode::CREATED,
                Json(ApiResponse::success(user.to_public())),
            ))
        }
        Err(crate::error::DataChainError::PasswordRejected(msg)) => {
            Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error(msg))))
        }
        // 存储故障/数据损坏/内部错误:500,详情只进日志,不回显给客户端。
        Err(
            e @ (crate::error::DataChainError::Internal(_)
            | crate::error::DataChainError::DatabaseError(_)
            | crate::error::DataChainError::StorageError(_)
            | crate::error::DataChainError::DataCorruption { .. }),
        ) => {
            tracing::error!("注册失败(内部错误): {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("internal error")),
            ))
        }
        // UserExists 及其余错误保持 400 + 原文案。
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

/// 提取请求的客户端上下文(会话与审计用)。IP 取自限流中间件解析出的 `ClientIp`
/// (默认只用对端地址;仅对端属于可信代理时才采用 X-Forwarded-For)。
fn client_context(client_ip: Option<Extension<ClientIp>>, headers: &HeaderMap) -> LoginContext {
    LoginContext {
        client_ip: client_ip
            .and_then(|Extension(ClientIp(ip))| ip)
            .map(|ip| ip.to_string()),
        user_agent: headers
            .get(header::USER_AGENT)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()),
    }
}

pub async fn login(
    State(state): State<AppState>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> axum::response::Response {
    let ctx = client_context(client_ip, &headers);
    match state.auth_service.login(&req, &ctx).await {
        Ok(resp) => (StatusCode::OK, Json(ApiResponse::success(resp))).into_response(),
        Err(crate::error::DataChainError::TooManyAttempts { retry_after_secs }) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
            Json(ApiResponse::error("too many attempts")),
        )
            .into_response(),
        Err(crate::error::DataChainError::InvalidCredentials) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::error("invalid credentials")),
        )
            .into_response(),
        Err(e) => {
            // 数据损坏(DataCorruption)与存储等内部故障一律 500,
            // 不伪装成凭证错误,也不向客户端泄露细节(详情仅写日志)。
            tracing::error!("登录失败(内部错误): {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("internal error")),
            )
                .into_response()
        }
    }
}

pub async fn get_profile(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.auth_service.get_user_by_id(&claims.sub) {
        Ok(user) => Ok(Json(ApiResponse::success(user.to_public()))),
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

/// 内部错误统一响应:不向客户端泄露存储细节。
fn internal_error(context: &str, e: crate::error::DataChainError) -> axum::response::Response {
    tracing::error!("{}: {}", context, e);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse::error("internal error")),
    )
        .into_response()
}

/// `POST /api/v1/auth/logout`:撤销当前会话(幂等),204。
pub async fn logout(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let ctx = client_context(client_ip, &headers);
    match state.auth_service.logout(&claims, &ctx).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => internal_error("登出失败", e),
    }
}

/// `POST /api/v1/auth/logout-all`:撤销该用户全部会话(幂等),204。
pub async fn logout_all(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let ctx = client_context(client_ip, &headers);
    match state.auth_service.logout_all(&claims.sub, &ctx).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => internal_error("全部登出失败", e),
    }
}

/// `POST /api/v1/auth/password`:修改本人密码,成功 204 无体。
/// 400 固定词表(策略/新旧相同)、401 invalid credentials(旧密码错或并发改密落败)、
/// 429 + Retry-After、500 internal error。缺字段由 `Json` 提取器返回 422。
pub async fn change_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> axum::response::Response {
    use crate::error::DataChainError;
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .change_password(&claims, &req, &ctx)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DataChainError::PasswordRejected(msg)) => {
            (StatusCode::BAD_REQUEST, Json(ApiResponse::error(msg))).into_response()
        }
        Err(DataChainError::InvalidCredentials) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::error("invalid credentials")),
        )
            .into_response(),
        Err(DataChainError::TooManyAttempts { retry_after_secs }) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
            Json(ApiResponse::error("too many attempts")),
        )
            .into_response(),
        Err(e) => internal_error("修改密码失败", e),
    }
}

/// `GET /api/v1/auth/sessions`:列出当前用户的有效会话。
pub async fn list_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> axum::response::Response {
    match state
        .auth_service
        .list_sessions(&claims.sub, claims.sid.as_deref())
        .await
    {
        Ok(sessions) => Json(ApiResponse::success(sessions)).into_response(),
        Err(e) => internal_error("查询会话失败", e),
    }
}

/// `DELETE /api/v1/auth/sessions/:id`:撤销本人名下的指定会话。
/// 非本人、不存在或已失效统一 404,避免枚举他人会话。
pub async fn delete_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(session_id): Path<String>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .revoke_user_session(&claims.sub, &session_id, &ctx)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("session not found")),
        )
            .into_response(),
        Err(e) => internal_error("撤销会话失败", e),
    }
}

// ==================== 管理员处理器 ====================

/// 管理员接口二次断言:中间件已按路径校验过权限,handler 内再确认一次(纵深防御)。
/// 无权限时返回 403 响应,有权限返回 `None`。
fn admin_denied(
    claims: &Claims,
    permission: crate::auth::Permission,
) -> Option<axum::response::Response> {
    let allowed = claims
        .role
        .parse::<crate::auth::Role>()
        .map(|role| crate::auth::check_permission(role, permission))
        .unwrap_or(false);
    if allowed {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(ApiResponse::error("permission denied")),
            )
                .into_response(),
        )
    }
}

/// 管理员接口的错误映射:未知用户 404、自停用 409、其余 500(不泄露细节)。
fn admin_error(context: &str, e: crate::error::DataChainError) -> axum::response::Response {
    use crate::error::DataChainError;
    match e {
        DataChainError::UserNotFound(_) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("user not found")),
        )
            .into_response(),
        DataChainError::SelfDeactivation => (
            StatusCode::CONFLICT,
            Json(ApiResponse::error("cannot deactivate yourself")),
        )
            .into_response(),
        DataChainError::LastAdminProtected => (
            StatusCode::CONFLICT,
            Json(ApiResponse::error(
                "cannot deactivate the last active admin",
            )),
        )
            .into_response(),
        e => internal_error(context, e),
    }
}

/// `GET /api/v1/admin/users/:user_id/sessions`:管理员列出目标用户的有效会话。
pub async fn admin_list_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(resp) = admin_denied(&claims, crate::auth::Permission::UserSessionAdmin) {
        return resp;
    }
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .admin_list_sessions(&claims.sub, &user_id, &ctx)
        .await
    {
        Ok(sessions) => Json(ApiResponse::success(sessions)).into_response(),
        Err(e) => admin_error("管理员查询会话失败", e),
    }
}

/// `DELETE /api/v1/admin/users/:user_id/sessions`:管理员撤销目标用户全部会话(幂等)。
pub async fn admin_revoke_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(resp) = admin_denied(&claims, crate::auth::Permission::UserSessionAdmin) {
        return resp;
    }
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .admin_revoke_sessions(&claims.sub, &user_id, &ctx)
        .await
    {
        Ok(revoked) => Json(ApiResponse::success(
            serde_json::json!({ "revoked": revoked }),
        ))
        .into_response(),
        Err(e) => admin_error("管理员撤销会话失败", e),
    }
}

/// `POST /api/v1/admin/users/:user_id/deactivate`:停用用户并撤销其全部会话(幂等)。
/// 目标为操作者本人返回 409。
pub async fn admin_deactivate_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(resp) = admin_denied(&claims, crate::auth::Permission::UserStatusAdmin) {
        return resp;
    }
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .deactivate_user_by(Some(&claims.sub), &user_id, &ctx)
        .await
    {
        Ok(revoked) => Json(ApiResponse::success(serde_json::json!({
            "user_id": user_id,
            "is_active": false,
            "revoked_sessions": revoked,
        })))
        .into_response(),
        Err(e) => admin_error("管理员停用用户失败", e),
    }
}

/// `POST /api/v1/admin/users/:user_id/activate`:启用用户(幂等,不恢复旧会话)。
pub async fn admin_activate_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(resp) = admin_denied(&claims, crate::auth::Permission::UserStatusAdmin) {
        return resp;
    }
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .activate_user_by(Some(&claims.sub), &user_id, &ctx)
        .await
    {
        Ok(()) => Json(ApiResponse::success(serde_json::json!({
            "user_id": user_id,
            "is_active": true,
        })))
        .into_response(),
        Err(e) => admin_error("管理员启用用户失败", e),
    }
}

/// `POST /api/v1/admin/users/:user_id/unlock`:清除目标用户的登录锁定与失败计数(幂等)。
pub async fn admin_unlock_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(resp) = admin_denied(&claims, crate::auth::Permission::UserStatusAdmin) {
        return resp;
    }
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .unlock_user(Some(&claims.sub), &user_id, &ctx)
        .await
    {
        Ok(outcome) => Json(ApiResponse::success(serde_json::json!({
            "user_id": user_id,
            "unlocked": outcome.locks_cleared > 0,
        })))
        .into_response(),
        Err(e) => admin_error("管理员解锁用户失败", e),
    }
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    State(state): State<AppState>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let ctx = client_context(client_ip, &headers);
    match state
        .auth_service
        .refresh_token_with_context(&req.refresh_token, &ctx)
        .await
    {
        Ok(resp) => Ok(Json(ApiResponse::success(resp))),
        Err(e) => {
            // 区分 HTTP 语义：令牌无效/过期/复用等客户端凭证问题 => 401；
            // 底层数据库/存储故障 => 500，避免把服务端故障伪装成鉴权失败而掩盖问题。
            // 数据损坏(DataCorruption)同属服务端故障 => 500,且不向客户端泄露细节(仅写日志)。
            match e {
                crate::error::DataChainError::DatabaseError(_)
                | crate::error::DataChainError::StorageError(_)
                | crate::error::DataChainError::DataCorruption { .. } => {
                    tracing::error!("刷新令牌失败(内部错误): {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::error("internal error")),
                    ))
                }
                _ => Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ApiResponse::error(e.to_string())),
                )),
            }
        }
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
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(e.to_string())),
                ));
            }
            state.event_bus.publish(Event::new(
                EventType::MetadataCreated,
                serde_json::to_value(&entry).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(entry))))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

pub async fn get_metadata(
    State(state): State<AppState>,
    Path(data_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.metadata_manager.get_by_data_id(&data_id).await {
        Ok(Some(entry)) => Ok(Json(ApiResponse::success(entry))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("metadata not found")),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

pub async fn query_metadata(
    State(state): State<AppState>,
    Query(mut req): Query<QueryMetadataRequest>,
) -> Result<Json<PaginatedResponse<crate::core::MetadataEntry>>, (StatusCode, Json<ApiResponse<()>>)>
{
    if req.page == 0 {
        req.page = 1;
    }
    if req.page_size == 0 {
        req.page_size = 20;
    }

    let results = state.metadata_manager.query(&req).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(e.to_string())),
        )
    })?;
    Ok(Json(PaginatedResponse {
        total: results.len(),
        data: results,
        page: req.page,
        page_size: req.page_size,
    }))
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
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

pub async fn get_chain_info(
    State(state): State<AppState>,
) -> Json<ApiResponse<crate::core::ChainInfo>> {
    let info = state.chain.get_chain_info();
    Json(ApiResponse::success(info))
}

pub async fn mine_block(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // 检查权限
    if claims.role != "admin" && claims.role != "user" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error("permission denied")),
        ));
    }

    let _gate = state.identity_tx_gate.lock().await;
    match state.chain.mine_block_with_identity_transaction_ids() {
        Ok(mut mined) => {
            // 挖矿后计算当前身份集快照哈希并写入区块头(backlog L1)。
            // snapshot_hash 派生自已进 merkle 的 key_transactions,不参与 PoW 哈希,
            // 故此处填入不影响区块 hash;同步更新链内副本,保证与持久化一致。
            let key_set = crate::identity::replay_key_set(&state.chain.get_all_blocks());
            let snapshot = crate::identity::compute_identity_snapshot_hash(&key_set);
            if !snapshot.is_empty() {
                mined.block.identity_snapshot_hash = snapshot.clone();
                state
                    .chain
                    .set_latest_identity_snapshot(&mined.block, &snapshot);
            }
            // 传入与本次 key transaction 逐项对齐的身份账本映射；`None` 保留普通
            // 交易位置，防止共享 DSN 的其他 AppState 误提交未包含在本区块的交易。
            if let Err(e) = state
                .storage
                .commit_block(&mined.block, &mined.identity_transaction_ids)
                .await
            {
                state
                    .chain
                    .rollback_mined_block_with_identity_transaction_ids(&mined);
                tracing::error!("提交区块失败: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(e.to_string())),
                ));
            }
            state.event_bus.publish(Event::new(
                EventType::BlockMined,
                serde_json::to_value(&mined.block).unwrap_or_else(|_| serde_json::json!({})),
            ));
            // 挖矿成功后向已注册 peer 主动广播新区块(异步,不阻塞响应)。
            let p2p = state.p2p.clone();
            let broadcast_block = mined.block.clone();
            tokio::spawn(async move {
                p2p.broadcast_blocks(vec![broadcast_block]).await;
            });
            Ok((StatusCode::CREATED, Json(ApiResponse::success(mined.block))))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

#[derive(Serialize)]
pub struct CorruptionInfo {
    pub category: &'static str,
    pub table: &'static str,
    pub key: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub block_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corruption: Option<CorruptionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_block: Option<i64>,
}

/// `{valid,block_count}` 字段语义不变(来自内存 Chain);新增只读扫描存储权威源,
/// 检测是否存在数据损坏,仅在非空时附加 corruption/invalid_block。
/// 状态码始终 200,不因损坏或链无效而改变(与此前行为兼容)。
pub async fn validate_chain(State(state): State<AppState>) -> Json<ApiResponse<ValidateResponse>> {
    let valid = state.chain.validate_chain();
    let block_count = state.chain.get_block_count();

    let mut corruption = None;
    let mut invalid_block = None;

    match state.storage.get_all_blocks().await {
        Err(crate::error::DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        }) => {
            corruption = Some(CorruptionInfo {
                category: match category {
                    crate::error::CorruptionCategory::Authoritative => "authoritative",
                    crate::error::CorruptionCategory::Rebuildable => "rebuildable",
                },
                table,
                key,
                reason,
            });
        }
        Err(_) => {}
        Ok(_) => {
            if !valid {
                invalid_block = crate::core::Chain::find_first_invalid_block_index(
                    &state.chain.get_all_blocks(),
                );
            }
        }
    }

    state.event_bus.publish(Event::new(
        EventType::ChainValidated,
        serde_json::json!({ "valid": valid, "block_count": block_count }),
    ));
    Json(ApiResponse::success(ValidateResponse {
        valid,
        block_count,
        corruption,
        invalid_block,
    }))
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
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("version not found")),
        )),
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
            Self::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, Json(ApiResponse::error(message)))
            }
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
    if input
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(VersionPathValidationError::BadRequest(
            "file_path 包含不允许的路径穿越组件".to_string(),
        ));
    }

    let configured_root = std::env::var_os("DATACHAIN_VERSION_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let root = fs::canonicalize(&configured_root).map_err(|error| {
        VersionPathValidationError::Forbidden(format!("版本根目录不可用: {}", error))
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
    let safe_path =
        validate_version_path(&req.file_path).map_err(VersionPathValidationError::response)?;
    let safe_path = safe_path.to_string_lossy().into_owned();
    let previous_version_id = state
        .version_tracker
        .get_latest_version(&safe_path)
        .map(|version| version.version_id);

    match state
        .version_tracker
        .track_file(&safe_path, &claims.username, &req.message)
    {
        Ok(version) => {
            // 同内容返回既有版本；只有真正的新版本才写入数据库，避免重复 version_id 冲突。
            let is_new_version =
                previous_version_id.as_deref() != Some(version.version_id.as_str());
            if is_new_version {
                if let Err(e) = state.storage.save_version(&version).await {
                    state.version_tracker.remove_version(&version.version_id);
                    tracing::error!("保存版本失败: {}", e);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::error(e.to_string())),
                    ));
                }
            }
            state.event_bus.publish(Event::new(
                EventType::VersionTracked,
                serde_json::to_value(&version).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(version))))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

pub async fn get_version_history(
    State(state): State<AppState>,
    Path(file_path): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let safe_path =
        validate_version_path(&file_path).map_err(VersionPathValidationError::response)?;
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
    match state
        .version_tracker
        .get_version_diff(&old_version_id, &new_version_id)
    {
        Ok(diff) => Ok(Json(ApiResponse::success(diff))),
        Err(crate::error::DataChainError::VersionNotFound(version_id)) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error(format!(
                "version not found: {}",
                version_id
            ))),
        )),
        Err(crate::error::DataChainError::IoError(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Err((
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("版本内容快照不可用")),
            ))
        }
        Err(crate::error::DataChainError::StorageError(message)) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse::error(message)),
        )),
        Err(error) => {
            tracing::error!("读取版本快照失败: {}", error);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(error.to_string())),
            ))
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

pub async fn aggregation_status(
    State(state): State<AppState>,
) -> Json<ApiResponse<crate::aggregation::SchedulerStatus>> {
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
                state
                    .aggregation_engine
                    .remove_aggregation(&summary.summary_id);
                tracing::error!("保存聚合结果失败: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(e.to_string())),
                ));
            }
            state.event_bus.publish(Event::new(
                EventType::AggregationDone,
                serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({})),
            ));
            Ok((StatusCode::CREATED, Json(ApiResponse::success(summary))))
        }
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("aggregation failed or no data")),
        )),
    }
}

// ==================== P2P 同步处理器 ====================

pub async fn list_peers(
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<crate::p2p::PeerInfo>>> {
    Json(ApiResponse::success(state.p2p.list_peers()))
}

pub async fn register_peer(
    State(state): State<AppState>,
    Json(req): Json<PeerRegistration>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    match state.p2p.register_peer(req) {
        Ok(peer) => Ok((StatusCode::CREATED, Json(ApiResponse::success(peer)))),
        Err(error) => Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(error.to_string())),
        )),
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
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("sync start is beyond local chain")),
        ));
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
            return Err((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(format!(
                    "block sync rejected after {} blocks: {}",
                    imported, error
                ))),
            ));
        }
        if let Err(error) = state.storage.save_block(&block).await {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(error.to_string())),
            ));
        }
        imported += 1;
    }
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "imported": imported }),
    )))
}

pub async fn sync_peer(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Result<Json<ApiResponse<crate::p2p::SyncReport>>, (StatusCode, Json<ApiResponse<()>>)> {
    match state.p2p.sync_peer(&peer_id, &state.chain).await {
        Ok(report) => Ok(Json(ApiResponse::success(report))),
        Err(error) => Err((
            StatusCode::BAD_GATEWAY,
            Json(ApiResponse::error(error.to_string())),
        )),
    }
}

// ==================== 统计处理器 ====================

#[derive(Serialize)]
pub struct StatsResponse {
    pub chain: crate::core::ChainInfo,
    pub metadata: crate::metadata::MetadataStatistics,
    pub versions: crate::versioning::VersionStatistics,
}

pub async fn get_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<StatsResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let chain = state.chain.get_chain_info();
    let metadata = state.metadata_manager.get_statistics().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(e.to_string())),
        )
    })?;
    let versions = state.version_tracker.get_statistics();

    Ok(Json(ApiResponse::success(StatsResponse {
        chain,
        metadata,
        versions,
    })))
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
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error(format!(
            "block not found with hash: {}",
            hash
        ))),
    ))
}

/// 完整 Merkle proof：返回叶子、索引、sibling/path 和根，可由目标链独立验证。
pub async fn get_merkle_proof(
    State(state): State<AppState>,
    Path(data_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    for block in state.chain.get_all_blocks() {
        if let Some(index) = block
            .metadata_list
            .iter()
            .position(|entry| entry.data_id == data_id)
        {
            let leaves = block
                .metadata_list
                .iter()
                .map(|entry| metadata_leaf_hash(&entry.data_id))
                .collect();
            let tree = MerkleTree::from_hashes(leaves);
            let proof = tree.get_structured_proof(index).ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error("failed to create merkle proof")),
                )
            })?;
            if proof.root != block.merkle_root || !MerkleTree::verify_structured_proof(&proof) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "stored block merkle proof is inconsistent",
                    )),
                ));
            }
            return Ok(Json(ApiResponse::success(serde_json::json!({
                "data_id": data_id,
                "block_index": block.index,
                "block_hash": block.hash,
                "merkle_root": block.merkle_root,
                "proof": proof,
            }))));
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error("data_id not found in committed blocks")),
    ))
}

#[derive(Deserialize)]
pub struct CreateAnchorRequest {
    /// 目标链标识；缺省时使用配置的默认目标链。
    #[serde(default)]
    pub target_chain_id: Option<String>,
}

/// 为某个已上链 data_id 生成跨链锚定（签名 + 入 outbox），由后台 worker 投递。
pub async fn create_anchor(
    State(state): State<AppState>,
    Path(data_id): Path<String>,
    body: Option<Json<CreateAnchorRequest>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let target_chain_id = body
        .and_then(|b| b.0.target_chain_id)
        .filter(|s| !s.trim().is_empty());

    for block in state.chain.get_all_blocks() {
        if let Some(index) = block
            .metadata_list
            .iter()
            .position(|entry| entry.data_id == data_id)
        {
            let leaves = block
                .metadata_list
                .iter()
                .map(|entry| metadata_leaf_hash(&entry.data_id))
                .collect();
            let tree = MerkleTree::from_hashes(leaves);
            let proof = tree.get_structured_proof(index).ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error("failed to create merkle proof")),
                )
            })?;
            if proof.root != block.merkle_root || !MerkleTree::verify_structured_proof(&proof) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(
                        "stored block merkle proof is inconsistent",
                    )),
                ));
            }
            let target = target_chain_id
                .unwrap_or_else(|| state.anchor_service.default_target_chain_id().to_string());
            let signed = state
                .anchor_service
                .enqueue_anchor(
                    target,
                    data_id.clone(),
                    block.hash.clone(),
                    block.merkle_root.clone(),
                    proof,
                )
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ApiResponse::error(format!(
                            "failed to enqueue anchor: {}",
                            e
                        ))),
                    )
                })?;
            return Ok(Json(ApiResponse::success(serde_json::json!({
                "anchor_id": signed.anchor.anchor_id,
                "source_chain_id": signed.anchor.source_chain_id,
                "source_node_id": signed.anchor.source_node_id,
                "target_chain_id": signed.anchor.target_chain_id,
                "data_id": signed.anchor.data_id,
                "block_hash": signed.anchor.block_hash,
                "merkle_root": signed.anchor.merkle_root,
                "public_key": signed.public_key,
                "signature": signed.signature,
                "status": "pending",
            }))));
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::error("data_id not found in committed blocks")),
    ))
}

/// 查询锚定投递状态与回执。
pub async fn get_anchor_status(
    State(state): State<AppState>,
    Path(anchor_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let entry = state.storage.get_anchor(&anchor_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(format!("failed to query anchor: {}", e))),
        )
    })?;
    match entry {
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("anchor not found")),
        )),
        Some(entry) => Ok(Json(ApiResponse::success(serde_json::json!({
            "anchor_id": entry.signed.anchor.anchor_id,
            "target_chain_id": entry.signed.anchor.target_chain_id,
            "data_id": entry.signed.anchor.data_id,
            "status": entry.status.as_str(),
            "attempts": entry.attempts,
            "last_error": entry.last_error,
            "receipt": entry.receipt,
        })))),
    }
}

/// 返回本节点公开身份（node_id + 公钥），供目标链/审计方验签。
pub async fn get_node_identity(
    State(state): State<AppState>,
) -> Json<ApiResponse<serde_json::Value>> {
    let identity = state.anchor_service.node_identity();
    Json(ApiResponse::success(serde_json::json!({
        "chain_id": state.anchor_service.chain_id(),
        "node_id": identity.node_id(),
        "public_key": identity.public_key_base64(),
    })))
}

// ==================== 链上身份处理器 (backlog L1) ====================

/// 提交一条密钥交易(register/revoke)。带 `Idempotency-Key` 的请求跨重试返回同一账本交易。
pub async fn submit_key_transaction(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Json(req): Json<crate::identity::KeyTransactionRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let idempotency_key = headers.get("idempotency-key").and_then(|value| {
        value
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    });
    let now = chrono::Utc::now().timestamp();
    let entry = crate::identity::build_verified_key_transaction(&req, now).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(e.to_string())),
        )
    })?;
    let request_fingerprint = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(entry.signing_payload()))
    };

    let _gate = state.identity_tx_gate.lock().await;
    let result = state
        .storage
        .create_or_get_identity_transaction(
            &claims.sub,
            idempotency_key.as_deref(),
            &request_fingerprint,
            &entry,
            now,
        )
        .await
        .map_err(|e| match e {
            crate::error::DataChainError::IdentityTransactionConflict => (
                StatusCode::CONFLICT,
                Json(ApiResponse::error(e.to_string())),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            ),
        })?;
    if result.created {
        state.chain.add_pending_key_transaction(
            result.transaction.transaction_id.clone(),
            result.transaction.entry.clone(),
        );
    }
    let status_code = if result.transaction.status == "committed" {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((
        status_code,
        Json(ApiResponse::success(serde_json::json!({
            "transaction_id": result.transaction.transaction_id,
            "tx_type": result.transaction.entry.tx_type,
            "target_key": result.transaction.entry.target_key,
            "signed_by": result.transaction.entry.signed_by,
            "timestamp": result.transaction.entry.timestamp,
            "status": result.transaction.status,
        }))),
    ))
}

/// 查询当前有效密钥集(重放链上 key_transactions)。
pub async fn list_identity_keys(
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<crate::identity::KeyRecord>>> {
    let set = crate::identity::replay_key_set(&state.chain.get_all_blocks());
    Json(ApiResponse::success(set.into_values().collect()))
}

/// 查询单个公钥的当前状态。
pub async fn get_identity_key(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> Result<Json<ApiResponse<crate::identity::KeyRecord>>, (StatusCode, Json<ApiResponse<()>>)> {
    let set = crate::identity::replay_key_set(&state.chain.get_all_blocks());
    match set.get(&public_key) {
        Some(rec) => Ok(Json(ApiResponse::success(rec.clone()))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("public key not found or revoked")),
        )),
    }
}

/// 提交完整语义目录记录(Subject/Revision/Artifact/Claim)。
///
/// 记录必须由已上链、当前有效的身份公钥签名。先持久化 pending 记录后入 Chain 内存队列，
/// 下次正常挖矿时进入 block.catalog_records 与 merkle_root；不另起特殊区块。
pub async fn submit_catalog_record(
    State(state): State<AppState>,
    Json(req): Json<crate::catalog::CatalogRecordRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let record =
        crate::catalog::CatalogRecord::from_verified_request(req, chrono::Utc::now().timestamp())
            .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(e.to_string())),
            )
        })?;

    // 签名数学正确还不够：签发公钥必须是本链当前有效身份，才能形成可追溯认证来源。
    let active_keys = crate::identity::replay_key_set(&state.chain.get_all_blocks());
    if !active_keys.contains_key(&record.issuer_key) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                "catalog issuer key is not an active on-chain identity",
            )),
        ));
    }

    let record_type = record.record_type();
    let primary_id = record.payload.primary_id().to_string();
    if state.chain.has_catalog_record(record_type, &primary_id) {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiResponse::error("catalog primary id already exists")),
        ));
    }

    // 关系完整性：允许引用同一待打包批次中的前置记录，但拒绝悬空关系。
    match &record.payload {
        crate::catalog::CatalogPayload::Subject(_) => {}
        crate::catalog::CatalogPayload::Revision(v) => {
            if !state.chain.has_catalog_record("subject", &v.subject_id) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error("referenced subject does not exist")),
                ));
            }
            if !v.parent_revision_id.is_empty()
                && !state
                    .chain
                    .has_catalog_record("revision", &v.parent_revision_id)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        "referenced parent revision does not exist",
                    )),
                ));
            }
        }
        crate::catalog::CatalogPayload::Artifact(v) => {
            if !state.chain.has_catalog_record("revision", &v.revision_id) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error("referenced revision does not exist")),
                ));
            }
        }
        crate::catalog::CatalogPayload::Claim(v) => {
            let subject_ok =
                v.subject_id.is_empty() || state.chain.has_catalog_record("subject", &v.subject_id);
            let revision_ok = v.revision_id.is_empty()
                || state.chain.has_catalog_record("revision", &v.revision_id);
            let artifact_ok = v.artifact_id.is_empty()
                || state.chain.has_catalog_record("artifact", &v.artifact_id);
            if !(subject_ok && revision_ok && artifact_ok) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error(
                        "claim references an unknown catalog object",
                    )),
                ));
            }
            if !v.supersedes_claim_id.is_empty()
                && !state
                    .chain
                    .has_catalog_record("claim", &v.supersedes_claim_id)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error("superseded claim does not exist")),
                ));
            }
        }
    }

    // 先持久化，失败时不入内存队列；重启后 server 会从 pending_catalog_records 恢复。
    state
        .storage
        .save_pending_catalog_record(&record)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            )
        })?;
    state.chain.add_catalog_record(record.clone());

    Ok((
        StatusCode::ACCEPTED,
        Json(ApiResponse::success(serde_json::json!({
            "record_id": record.record_id,
            "record_type": record.record_type(),
            "primary_id": primary_id,
            "status": "pending",
        }))),
    ))
}

/// 查询一个逻辑对象及其初始登记记录。
pub async fn get_catalog_subject(
    State(state): State<AppState>,
    Path(subject_id): Path<String>,
) -> Result<Json<ApiResponse<crate::catalog::CatalogRecord>>, (StatusCode, Json<ApiResponse<()>>)> {
    match state.storage.get_catalog_subject(&subject_id).await {
        Ok(Some(record)) => Ok(Json(ApiResponse::success(record))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("catalog subject not found")),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(e.to_string())),
        )),
    }
}

/// 查询逻辑对象的全部已上链不可变版本。
pub async fn get_catalog_revisions(
    State(state): State<AppState>,
    Path(subject_id): Path<String>,
) -> Result<
    Json<ApiResponse<Vec<crate::catalog::CatalogRecord>>>,
    (StatusCode, Json<ApiResponse<()>>),
> {
    state
        .storage
        .get_catalog_revisions(&subject_id)
        .await
        .map(|records| Json(ApiResponse::success(records)))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            )
        })
}

/// 查询一个不可变版本的构建/配置变体。
pub async fn get_catalog_artifacts(
    State(state): State<AppState>,
    Path(revision_id): Path<String>,
) -> Result<
    Json<ApiResponse<Vec<crate::catalog::CatalogRecord>>>,
    (StatusCode, Json<ApiResponse<()>>),
> {
    state
        .storage
        .get_catalog_artifacts(&revision_id)
        .await
        .map(|records| Json(ApiResponse::success(records)))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            )
        })
}

/// 查询逻辑对象全部认证声明历史（含 withdrawn/superseded，追溯不丢历史）。
pub async fn get_catalog_claims(
    State(state): State<AppState>,
    Path(subject_id): Path<String>,
) -> Result<
    Json<ApiResponse<Vec<crate::catalog::CatalogRecord>>>,
    (StatusCode, Json<ApiResponse<()>>),
> {
    state
        .storage
        .get_catalog_claims(&subject_id)
        .await
        .map(|records| Json(ApiResponse::success(records)))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            )
        })
}

/// 按当前信任策略解析指定时间点的有效 Claim；同权重不同状态会明确返回 conflicts。
#[derive(Debug, Deserialize)]
pub struct EffectiveClaimsQuery {
    pub as_of: Option<i64>,
}

pub async fn get_effective_catalog_claims(
    State(state): State<AppState>,
    Path(subject_id): Path<String>,
    Query(query): Query<EffectiveClaimsQuery>,
) -> Result<Json<ApiResponse<crate::catalog::ClaimResolution>>, (StatusCode, Json<ApiResponse<()>>)>
{
    let records = state
        .storage
        .get_catalog_claims_at_block(&subject_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(e.to_string())),
            )
        })?;
    let as_of = query
        .as_of
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    Ok(Json(ApiResponse::success(
        state.claim_resolver.resolve(records, as_of),
    )))
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
        assert!(matches!(
            result,
            Err(VersionPathValidationError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_directories_as_version_files() {
        let root = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(root).unwrap();
        let result = validate_version_path(directory.path().to_str().unwrap());
        assert!(matches!(
            result,
            Err(VersionPathValidationError::BadRequest(_))
        ));
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
