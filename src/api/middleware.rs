use axum::{
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::Response,
};

use super::AppState;
use crate::auth::{check_permission, Claims, Permission, Role};

// axum 0.7 变更:Next 不再有泛型参数,Request 默认具体化为 Request<Body>。
// 原代码沿用 0.6 的 Next<B>/Request<B> 泛型写法,已不兼容,故去除泛型。

/// 根据 HTTP 方法和路径映射所需权限。
fn required_permission(method: &Method, path: &str) -> Option<Permission> {
    if method == Method::POST && path == "/api/v1/metadata" {
        return Some(Permission::MetadataCreate);
    }
    if path == "/api/v1/metadata" || path.starts_with("/api/v1/metadata/") {
        return Some(if method == Method::GET {
            Permission::MetadataRead
        } else {
            Permission::MetadataUpdate
        });
    }
    if method == Method::POST && path == "/api/v1/chain/mine" {
        return Some(Permission::BlockMine);
    }
    if path == "/api/v1/blocks"
        || path.starts_with("/api/v1/blocks/")
        || path == "/api/v1/chain/info"
        || path == "/api/v1/chain/validate"
    {
        return Some(Permission::BlockRead);
    }
    // 跨链锚定：生成锚定属于特权写操作，查询/证明/身份按读处理。
    if method == Method::POST && path.starts_with("/api/v1/crosschain/anchor/") {
        return Some(Permission::BlockMine);
    }
    if path.starts_with("/api/v1/crosschain/") {
        return Some(Permission::BlockRead);
    }
    // 链上身份:提交密钥交易属特权写(进区块),按 BlockMine;查询密钥集按 BlockRead。
    if method == Method::POST && path == "/api/v1/identity/key-transaction" {
        return Some(Permission::BlockMine);
    }
    if path.starts_with("/api/v1/identity/") {
        return Some(Permission::BlockRead);
    }
    // 语义目录:提交记录会进入区块,需 BlockMine;对象/版本/声明查询按 BlockRead。
    if method == Method::POST && path == "/api/v1/catalog/records" {
        return Some(Permission::BlockMine);
    }
    if path.starts_with("/api/v1/catalog/") {
        return Some(Permission::BlockRead);
    }
    if path == "/api/v1/versions/track" {
        return Some(Permission::VersionTrack);
    }
    if path == "/api/v1/versions" || path.starts_with("/api/v1/versions/") {
        return Some(Permission::VersionRead);
    }
    if method == Method::POST && path == "/api/v1/aggregations/trigger" {
        return Some(Permission::AggregationTrigger);
    }
    if path == "/api/v1/aggregations" || path.starts_with("/api/v1/aggregations/") {
        return Some(Permission::AggregationRead);
    }
    if path == "/api/v1/stats" {
        return Some(Permission::StatsRead);
    }
    if path == "/api/v1/peers" {
        return Some(Permission::SystemMonitor);
    }
    if path == "/api/v1/peers/register" || path.starts_with("/api/v1/peers/") {
        return Some(Permission::SystemAdmin);
    }
    if path == "/api/v1/sync/blocks" && method == Method::GET {
        return Some(Permission::BlockRead);
    }
    if path == "/api/v1/sync/blocks" {
        return Some(Permission::SystemAdmin);
    }
    // 管理员接口:整个前缀 fail-closed,未知子路径也要求 SystemAdmin。
    if is_admin_path(path) {
        if let Some(rest) = path.strip_prefix("/api/v1/admin/users/") {
            // rest 形如 `<user_id>/sessions` 或 `<user_id>/deactivate`。
            let mut parts = rest.split('/');
            let user_id = parts.next();
            let action = parts.next();
            let extra = parts.next();
            if user_id.is_some_and(|u| !u.is_empty()) && extra.is_none() {
                match (action, method) {
                    (Some("sessions"), &Method::GET | &Method::DELETE) => {
                        return Some(Permission::UserSessionAdmin);
                    }
                    (Some("deactivate" | "activate"), &Method::POST) => {
                        return Some(Permission::UserStatusAdmin);
                    }
                    _ => {}
                }
            }
        }
        return Some(Permission::SystemAdmin);
    }
    None
}

/// 认证中间件:校验 JWT、会话、账户状态、token 角色新鲜度和路由权限。
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") && h.len() > 7 => &h[7..],
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // 统一校验:JWT → 会话 → 用户状态 → 角色一致;任一步失败(含查库失败)均 401。
    let claims = state
        .auth_service
        .authenticate_access_token(token)
        .await
        .map_err(|e| {
            tracing::debug!("access token rejected: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    if let Some(permission) = required_permission(request.method(), request.uri().path()) {
        let role = claims
            .role
            .parse::<Role>()
            .map_err(|_| StatusCode::FORBIDDEN)?;
        if !check_permission(role, permission) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// 管理员前缀(`/api/v1/admin`)是否覆盖该路径。
fn is_admin_path(path: &str) -> bool {
    path == "/api/v1/admin" || path.starts_with("/api/v1/admin/")
}

/// 兜底路由专用:仅对 `/api/v1/admin` 前缀下未实现的路径先做认证与权限校验,
/// 使非管理员得 403、无 token 得 401(fail-closed),管理员才看到 404;其余路径保持原 404。
pub async fn admin_prefix_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    use axum::response::IntoResponse;
    if is_admin_path(request.uri().path()) {
        match auth_middleware(State(state), request, next).await {
            Ok(response) => response,
            Err(status) => status.into_response(),
        }
    } else {
        next.run(request).await
    }
}

/// 从请求中提取用户信息
pub fn extract_claims(request: &Request) -> Option<&Claims> {
    request.extensions().get::<Claims>()
}

/// 可选认证中间件（不强制要求认证）
pub async fn optional_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // 尝试获取 Authorization header
    if let Some(auth_header) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if auth_header.starts_with("Bearer ") {
            let token = &auth_header[7..];
            // 与强制认证共用同一校验;失败(含已撤销会话)视为匿名,不返回 401。
            if let Ok(claims) = state.auth_service.authenticate_access_token(token).await {
                request.extensions_mut().insert(claims);
            }
        }
    }

    next.run(request).await
}
