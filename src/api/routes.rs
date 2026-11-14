use axum::{
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use super::{
    handlers,
    middleware::{admin_prefix_auth, auth_middleware},
    rate_limit::rate_limit_middleware,
    websocket, AppState,
};

/// 创建路由
pub fn create_router(state: AppState) -> Router {
    // CORS 仅允许显式配置的来源；未配置时只允许本地开发来源。
    let configured_origins = std::env::var("DATACHAIN_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173".to_string());
    let origins: Vec<HeaderValue> = configured_origins
        .split(',')
        .filter_map(|origin| HeaderValue::from_str(origin.trim()).ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
        ]);

    // 公开路由（无需认证）
    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/api/v1/auth/register", post(handlers::register))
        .route("/api/v1/auth/login", post(handlers::login))
        .route("/api/v1/auth/refresh", post(handlers::refresh_token));

    // WebSocket 路由
    let ws_routes = Router::new()
        .route("/ws", get(websocket::ws_handler))
        .route("/ws/chain", get(websocket::chain_ws_handler))
        .route("/ws/metadata", get(websocket::metadata_ws_handler))
        .route("/ws/aggregation", get(websocket::aggregation_ws_handler))
        // WebSocket 握手也必须携带 Bearer JWT。
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // 需要认证的路由
    let protected_routes = Router::new()
        // 用户
        .route("/api/v1/auth/profile", get(handlers::get_profile))
        .route("/api/v1/auth/logout", post(handlers::logout))
        .route("/api/v1/auth/logout-all", post(handlers::logout_all))
        .route("/api/v1/auth/password", post(handlers::change_password))
        .route("/api/v1/auth/sessions", get(handlers::list_sessions))
        .route(
            "/api/v1/auth/sessions/:id",
            delete(handlers::delete_session),
        )
        // 管理员(前缀由 auth_middleware 统一 fail-closed)
        .route(
            "/api/v1/admin/users/:user_id/sessions",
            get(handlers::admin_list_sessions).delete(handlers::admin_revoke_sessions),
        )
        .route(
            "/api/v1/admin/users/:user_id/deactivate",
            post(handlers::admin_deactivate_user),
        )
        .route(
            "/api/v1/admin/users/:user_id/activate",
            post(handlers::admin_activate_user),
        )
        .route(
            "/api/v1/admin/users/:user_id/unlock",
            post(handlers::admin_unlock_user),
        )
        // 元数据
        .route("/api/v1/metadata", post(handlers::create_metadata))
        .route("/api/v1/metadata", get(handlers::query_metadata))
        .route("/api/v1/metadata/:id", get(handlers::get_metadata))
        // 区块链
        .route("/api/v1/blocks", get(handlers::get_blocks))
        .route("/api/v1/blocks/:index", get(handlers::get_block))
        .route(
            "/api/v1/blocks/by-hash/:hash",
            get(handlers::get_block_by_hash),
        )
        .route("/api/v1/blocks/proof/:sha256", get(handlers::get_proof))
        .route(
            "/api/v1/crosschain/proof/:data_id",
            get(handlers::get_merkle_proof),
        )
        .route(
            "/api/v1/crosschain/anchor/:data_id",
            post(handlers::create_anchor),
        )
        .route(
            "/api/v1/crosschain/anchor/status/:anchor_id",
            get(handlers::get_anchor_status),
        )
        .route(
            "/api/v1/crosschain/identity",
            get(handlers::get_node_identity),
        )
        .route(
            "/api/v1/identity/key-transaction",
            post(handlers::submit_key_transaction),
        )
        .route("/api/v1/identity/keys", get(handlers::list_identity_keys))
        .route(
            "/api/v1/identity/keys/:public_key",
            get(handlers::get_identity_key),
        )
        // 可验证语义目录:对象→版本→构建变体 + 带证据的认证声明
        .route(
            "/api/v1/catalog/records",
            post(handlers::submit_catalog_record),
        )
        .route(
            "/api/v1/catalog/subjects/:subject_id",
            get(handlers::get_catalog_subject),
        )
        .route(
            "/api/v1/catalog/subjects/:subject_id/revisions",
            get(handlers::get_catalog_revisions),
        )
        .route(
            "/api/v1/catalog/revisions/:revision_id/artifacts",
            get(handlers::get_catalog_artifacts),
        )
        .route(
            "/api/v1/catalog/subjects/:subject_id/effective-claims",
            get(handlers::get_effective_catalog_claims),
        )
        .route(
            "/api/v1/catalog/subjects/:subject_id/claims",
            get(handlers::get_catalog_claims),
        )
        .route("/api/v1/chain/info", get(handlers::get_chain_info))
        .route("/api/v1/chain/mine", post(handlers::mine_block))
        .route("/api/v1/chain/validate", post(handlers::validate_chain))
        // 版本
        .route("/api/v1/versions", get(handlers::get_versions))
        .route("/api/v1/versions/:id", get(handlers::get_version))
        .route("/api/v1/versions/track", post(handlers::track_version))
        .route(
            "/api/v1/versions/diff/:old_version_id/:new_version_id",
            get(handlers::get_version_diff),
        )
        .route(
            "/api/v1/versions/history/*file_path",
            get(handlers::get_version_history),
        )
        // 汇总
        .route("/api/v1/aggregations", get(handlers::get_aggregations))
        .route(
            "/api/v1/aggregations/status",
            get(handlers::aggregation_status),
        )
        .route(
            "/api/v1/aggregations/trigger",
            post(handlers::trigger_aggregation),
        )
        // 统计
        .route("/api/v1/stats", get(handlers::get_stats))
        .route("/api/v1/peers", get(handlers::list_peers))
        .route("/api/v1/peers/register", post(handlers::register_peer))
        .route("/api/v1/peers/:peer_id/sync", post(handlers::sync_peer))
        .route("/api/v1/sync/blocks", get(handlers::export_blocks))
        .route("/api/v1/sync/blocks", post(handlers::import_blocks))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // 兜底路由:管理员前缀下未实现的路径也必须先过认证与权限(fail-closed),
    // 其余未知路径仍是 404。注意:`Router::merge` 只保留自定义 fallback,
    // 对其他路由器被 layer 包裹的默认 fallback 会丢弃,因此需显式声明。
    let fallback_routes = Router::new()
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_prefix_auth,
        ));

    // 合并路由
    Router::new()
        .merge(public_routes)
        .merge(ws_routes)
        .merge(protected_routes)
        .merge(fallback_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
}

/// 把 Router 转成携带对端地址(ConnectInfo)的 make-service。
/// TLS 与非 TLS 两条 serve 路径都必须经此转换,否则 handler/限流拿不到真实对端 IP。
pub fn make_service(
    router: Router,
) -> axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, std::net::SocketAddr> {
    router.into_make_service_with_connect_info::<std::net::SocketAddr>()
}

/// 运行服务器
pub async fn run_server(
    state: AppState,
    addr: &str,
    tls_cert: Option<String>,
    tls_key: Option<String>,
) -> anyhow::Result<()> {
    let app = create_router(state);
    let socket_addr: std::net::SocketAddr = addr.parse()?;

    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
        tracing::info!("服务器启动于 HTTPS://{}", addr);
        axum_server::bind_rustls(socket_addr, tls_config)
            .serve(make_service(app))
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(socket_addr).await?;
        tracing::info!("服务器启动于 HTTP://{}", addr);
        axum::serve(listener, make_service(app)).await?;
    }

    Ok(())
}
