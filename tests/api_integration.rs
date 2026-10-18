//! API 集成测试:在进程内用 tower oneshot 驱动真实 Router,覆盖认证、RBAC 越权、
//! 端到端业务流(注册→登录→元数据→挖矿→跨链锚定)与 SQLite 重启恢复。
//!
//! 不走网络;P2P 双节点广播/发现路径已由 247 双容器 smoke 验证(见 R6 commit)。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, EventBus, NotificationService, WsHub};
use datachain::auth::{create_auth_service, RegisterRequest, Role};
use datachain::core::create_chain;
use datachain::crosschain::AnchorService;
use datachain::metadata::create_metadata_manager;
use datachain::node_signing::NodeIdentity;
use datachain::storage::create_storage;

const JWT_SECRET: &str = "integration-test-secret-key-0123456789-abcdef";

/// 构建完整 AppState,数据库落在给定 dsn(便于重启恢复测试复用同一文件)。
async fn build_state(dsn: &str) -> (AppState, Arc<datachain::storage::Storage>) {
    let storage = create_storage(dsn).await.unwrap();

    let chain = create_chain(2, 100);
    let blocks = storage.get_all_blocks().await.unwrap();
    if blocks.is_empty() {
        let genesis = chain.init();
        storage.save_block(&genesis).await.unwrap();
    } else {
        chain.load_blocks(blocks);
    }

    let auth_service = create_auth_service(JWT_SECRET.to_string(), 24);
    for user in storage.get_all_users().await.unwrap() {
        auth_service.load_user(user);
    }

    let metadata_manager = create_metadata_manager(chain.clone());
    let version_tracker = {
        // 版本内容快照目录用临时目录,避免污染工作区。
        let dir = tempfile::tempdir().unwrap().keep();
        Arc::new(datachain::versioning::VersionTracker::new_with_content_dir(dir).unwrap())
    };
    let aggregation_engine = create_aggregation_engine(chain.clone(), 3600, 100);
    for summary in storage.get_all_aggregations().await.unwrap() {
        aggregation_engine.load_aggregation(summary);
    }

    let ws_hub = WsHub::new();
    let notification = Arc::new(NotificationService::new(ws_hub.clone()));
    let event_bus = Arc::new(EventBus::new(notification));
    let scheduler = create_scheduler(aggregation_engine.clone(), 3600);
    let p2p = datachain::p2p::P2PService::with_node_id("test-node");
    let rate_limiter = Arc::new(api::RateLimiter::default());
    let anchor_service = Arc::new(AnchorService::new(
        Arc::new(NodeIdentity::generate("test-node")),
        "datachain-test",
        storage.clone(),
        None,
    ));

    let state = AppState {
        chain,
        auth_service,
        metadata_manager,
        version_tracker,
        aggregation_engine,
        storage: storage.clone(),
        ws_hub,
        event_bus,
        scheduler,
        p2p,
        rate_limiter,
        anchor_service,
    };
    (state, storage)
}

/// 直接用 register_with_role 建用户并持久化(公开注册只给 User 角色)。
async fn seed_user(state: &AppState, username: &str, password: &str, role: Role) {
    let req = RegisterRequest {
        username: username.to_string(),
        password: password.to_string(),
        email: format!("{}@test.local", username),
        role: Some(role),
    };
    let user = state.auth_service.register_with_role(&req, role).unwrap();
    state.storage.save_user(&user).await.unwrap();
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn post(uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {}", t));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {}", t));
    }
    builder.body(Body::empty()).unwrap()
}

async fn login(router: axum::Router, username: &str, password: &str) -> String {
    let resp = router
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            serde_json::json!({"username": username, "password": password}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "登录应成功");
    let json = body_json(resp).await;
    json["data"]["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn health_is_public() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    let router = api::create_router(state);

    let resp = router.oneshot(get("/health", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_route_requires_auth() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    let router = api::create_router(state);

    let resp = router
        .oneshot(get("/api/v1/chain/info", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rbac_user_cannot_create_anchor_admin_can() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    seed_user(&state, "bob", "bobpass123456", Role::User).await;
    let router = api::create_router(state);

    let admin_token = login(router.clone(), "admin", "adminpass123").await;
    let user_token = login(router.clone(), "bob", "bobpass123456").await;

    // admin 创建元数据并挖矿,得到一个可锚定的 data_id。
    let resp = router
        .clone()
        .oneshot(post(
            "/api/v1/metadata",
            Some(&admin_token),
            serde_json::json!({"data_size":10,"owner":"admin","hashes":{"sha256":"x"},"metadata":{},"tags":[]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&admin_token), Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let mined = body_json(resp).await;
    let data_id = mined["data"]["metadata_list"][0]["data_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 普通用户创建锚定 -> 403(需 BlockMine 权限)。
    let resp = router
        .clone()
        .oneshot(post(
            &format!("/api/v1/crosschain/anchor/{}", data_id),
            Some(&user_token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 普通用户读 proof -> 200(BlockRead)。
    let resp = router
        .clone()
        .oneshot(get(
            &format!("/api/v1/crosschain/proof/{}", data_id),
            Some(&user_token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // admin 创建锚定 -> 200 且状态 pending。
    let resp = router
        .clone()
        .oneshot(post(
            &format!("/api/v1/crosschain/anchor/{}", data_id),
            Some(&admin_token),
            serde_json::json!({"target_chain_id":"target-x"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let anchor = body_json(resp).await;
    assert_eq!(anchor["data"]["status"], "pending");
    assert!(!anchor["data"]["signature"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn sqlite_restart_recovers_blocks_and_users() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let dsn = dsn.to_str().unwrap();

    // 第一次启动:建 admin,挖一个含元数据的区块。
    {
        let (state, _) = build_state(dsn).await;
        seed_user(&state, "admin", "adminpass123", Role::Admin).await;
        let router = api::create_router(state);
        let token = login(router.clone(), "admin", "adminpass123").await;
        router
            .clone()
            .oneshot(post(
                "/api/v1/metadata",
                Some(&token),
                serde_json::json!({"data_size":5,"owner":"admin","hashes":{"sha256":"y"},"metadata":{},"tags":[]}),
            ))
            .await
            .unwrap();
        let resp = router
            .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // 第二次启动:同一 DSN 重建 state,应恢复区块与用户。
    {
        let (state, storage) = build_state(dsn).await;
        // 区块数 >= 2(创世 + 挖出的块)。
        assert!(storage.get_block_count().await.unwrap() >= 2);
        let router = api::create_router(state);
        // 旧 admin 仍可登录(用户已持久化)。
        let token = login(router.clone(), "admin", "adminpass123").await;
        let resp = router
            .oneshot(get("/api/v1/chain/info", Some(&token)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
