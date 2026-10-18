use axum::{
    http::{header, HeaderValue, Method},
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use super::{
    handlers, middleware::auth_middleware, rate_limit::rate_limit_middleware, websocket, AppState,
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
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

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

    // 合并路由
    Router::new()
        .merge(public_routes)
        .merge(ws_routes)
        .merge(protected_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
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
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(socket_addr).await?;
        tracing::info!("服务器启动于 HTTP://{}", addr);
        axum::serve(listener, app).await?;
    }

    Ok(())
}
