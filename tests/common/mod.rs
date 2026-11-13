//! 认证加固测试共用的最小 AppState 构建与 HTTP 辅助函数。
#![allow(dead_code)]

pub mod corrupt;

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::Value;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, EventBus, NotificationService, WsHub};
use datachain::auth::{create_auth_service, RegisterRequest, Role};
use datachain::core::create_chain;
use datachain::crosschain::AnchorService;
use datachain::metadata::create_metadata_manager;
use datachain::node_signing::NodeIdentity;
use datachain::storage::{create_storage, Storage};

pub const JWT_SECRET: &str = "integration-test-secret-key-0123456789-abcdef";

pub async fn build_state(dsn: &str) -> (AppState, Arc<Storage>) {
    let storage = create_storage(dsn).await.unwrap();

    let chain = create_chain(2, 100);
    let genesis = chain.init();
    storage.save_block(&genesis).await.unwrap();

    let auth_service = create_auth_service(JWT_SECRET.to_string(), 24, storage.clone());
    for user in storage.get_all_users().await.unwrap() {
        auth_service.load_user(user);
    }

    let metadata_manager = create_metadata_manager(chain.clone(), storage.clone());
    let version_tracker = {
        let dir = tempfile::tempdir().unwrap().keep();
        Arc::new(datachain::versioning::VersionTracker::new_with_content_dir(dir).unwrap())
    };
    let aggregation_engine = create_aggregation_engine(chain.clone(), 3600, 100);

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
        claim_resolver: Arc::new(datachain::catalog::ClaimResolver::new(Default::default())),
    };
    (state, storage)
}

/// 创建并持久化用户。
pub async fn seed_user(state: &AppState, username: &str, password: &str, role: Role) {
    let req = RegisterRequest {
        username: username.to_string(),
        password: password.to_string(),
        email: format!("{}@test.local", username),
        role: Some(role),
    };
    let user = state.auth_service.register_with_role(&req, role).unwrap();
    state.storage.save_user(&user).await.unwrap();
}

pub async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

pub fn post(uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {}", t));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

pub fn get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {}", t));
    }
    builder.body(Body::empty()).unwrap()
}
