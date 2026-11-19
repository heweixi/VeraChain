//! B17:`POST /api/v1/identity/key-transaction` 的 `Idempotency-Key` 长度上限。
//!
//! 规则:键经 trim 后按 UTF-8 字节计长,恰好 255 合法,超过 255 返回 400
//! `idempotency key too long`;检查发生在取 `identity_tx_gate`、写账本之前,
//! 超长请求不落账本也不入队。空白键与非 UTF-8 键仍视为未提供。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, EventBus, NotificationService, WsHub};
use datachain::auth::{create_auth_service, RegisterRequest, Role};
use datachain::core::{create_chain, KeyTransactionEntry};
use datachain::crosschain::AnchorService;
use datachain::metadata::create_metadata_manager;
use datachain::node_signing::NodeIdentity;
use datachain::storage::create_storage;

const JWT_SECRET: &str = "integration-test-secret-key-0123456789-abcdef";
const KEY_URI: &str = "/api/v1/identity/key-transaction";

/// 构建完整 AppState(沿用 api_integration.rs 的建法)。
async fn build_state(dsn: &str) -> (AppState, Arc<datachain::storage::Storage>) {
    let storage = create_storage(dsn).await.unwrap();

    let chain = create_chain(2, 100);
    let genesis = chain.init();
    storage.save_block(&genesis).await.unwrap();

    let auth_service = create_auth_service(JWT_SECRET.to_string(), 24, storage.clone());
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
        identity_tx_gate: Arc::new(tokio::sync::Mutex::new(())),
    };
    (state, storage)
}

async fn seed_admin(state: &AppState) {
    let req = RegisterRequest {
        username: "admin".to_string(),
        password: "adminpass123".to_string(),
        email: "admin@test.local".to_string(),
        role: Some(Role::Admin),
    };
    let user = state
        .auth_service
        .register_with_role(&req, Role::Admin)
        .unwrap();
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

async fn login(router: axum::Router) -> String {
    let resp = router
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            serde_json::json!({"username": "admin", "password": "adminpass123"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "登录应成功");
    body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// 与 api_integration.rs 的 `signed_key_tx_body` 相同:自签 register/revoke 请求体。
fn signed_key_tx_body(tx_type: &str, id: &NodeIdentity, role: &str) -> Value {
    let pk = id.public_key_base64();
    let probe = KeyTransactionEntry {
        tx_type: tx_type.to_string(),
        target_key: pk.clone(),
        role: role.to_string(),
        label: "node-a".to_string(),
        signed_by: pk.clone(),
        signature: String::new(),
        timestamp: 0,
        reason: String::new(),
    };
    let signature = id.sign_base64(&probe.signing_payload());
    serde_json::json!({
        "tx_type": tx_type,
        "target_key": pk,
        "role": role,
        "label": "node-a",
        "signed_by": pk,
        "signature": signature,
        "reason": ""
    })
}

fn keyed_request(token: &str, body: &Value, key: &[u8]) -> Request<Body> {
    let mut request = post(KEY_URI, Some(token), body.clone());
    request.headers_mut().insert(
        "idempotency-key",
        HeaderValue::from_bytes(key).expect("测试键必须是合法 HTTP header value"),
    );
    request
}

async fn setup(name: &str) -> (axum::Router, Arc<datachain::storage::Storage>, String) {
    let dir = tempfile::tempdir().unwrap().keep();
    let dsn = dir.join(name);
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    seed_admin(&state).await;
    let router = api::create_router(state);
    let token = login(router.clone()).await;
    (router, storage, token)
}

async fn pending_count(storage: &datachain::storage::Storage) -> usize {
    storage
        .get_pending_identity_transactions()
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn key_of_exactly_255_bytes_is_accepted_and_replays_same_transaction() {
    let (router, storage, token) = setup("limit-255.sqlite").await;
    let identity = NodeIdentity::generate("limit-255");
    let body = signed_key_tx_body("register", &identity, "node");
    let key = "a".repeat(255);

    let first = router
        .clone()
        .oneshot(keyed_request(&token, &body, key.as_bytes()))
        .await
        .unwrap();
    assert_eq!(
        first.status(),
        StatusCode::ACCEPTED,
        "恰好 255 字节必须合法"
    );
    let transaction_id = body_json(first).await["data"]["transaction_id"]
        .as_str()
        .expect("首次响应必须包含 transaction_id")
        .to_string();

    let replay = router
        .oneshot(keyed_request(&token, &body, key.as_bytes()))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        body_json(replay).await["data"]["transaction_id"],
        transaction_id,
        "255 字节键重放必须返回同一 transaction_id"
    );
    assert_eq!(pending_count(&storage).await, 1);
}

#[tokio::test]
async fn key_of_256_bytes_is_rejected_without_ledger_row_or_queue_entry() {
    let (router, storage, token) = setup("limit-256.sqlite").await;
    let identity = NodeIdentity::generate("limit-256");
    let body = signed_key_tx_body("register", &identity, "node");
    let key = "a".repeat(256);

    let rejected = router
        .clone()
        .oneshot(keyed_request(&token, &body, key.as_bytes()))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let rejected_body = body_json(rejected).await;
    assert_eq!(rejected_body["success"], false);
    assert_eq!(rejected_body["error"], "idempotency key too long");
    assert!(
        storage
            .get_pending_identity_transactions()
            .await
            .unwrap()
            .is_empty(),
        "超长键请求不得写入账本"
    );

    // 再提交一次合法键请求:只应产生 1 条 pending,且挖矿后只有 1 个有效密钥。
    let accepted = router
        .clone()
        .oneshot(keyed_request(&token, &body, b"short-key"))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    assert_eq!(pending_count(&storage).await, 1);

    let mined = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(mined.status(), StatusCode::CREATED);
    let keys = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/identity/keys")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let keys = body_json(keys).await;
    assert_eq!(keys["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        keys["data"][0]["public_key"],
        identity.public_key_base64(),
        "超长键请求不得进入内存待打包队列"
    );
}

#[tokio::test]
async fn length_is_measured_after_trim() {
    let (router, storage, token) = setup("limit-trim.sqlite").await;

    // trim 后恰好 255:前后各带空白仍应接受。
    let identity_ok = NodeIdentity::generate("limit-trim-ok");
    let body_ok = signed_key_tx_body("register", &identity_ok, "node");
    let padded_ok = format!("  {}\t ", "b".repeat(255));
    let accepted = router
        .clone()
        .oneshot(keyed_request(&token, &body_ok, padded_ok.as_bytes()))
        .await
        .unwrap();
    assert_eq!(
        accepted.status(),
        StatusCode::ACCEPTED,
        "trim 后 255 字节必须接受(trim 后计长)"
    );
    assert_eq!(pending_count(&storage).await, 1);

    // trim 后 256:带空白也必须拒绝。
    let identity_bad = NodeIdentity::generate("limit-trim-bad");
    let body_bad = signed_key_tx_body("register", &identity_bad, "node");
    let padded_bad = format!("  {} ", "c".repeat(256));
    let rejected = router
        .oneshot(keyed_request(&token, &body_bad, padded_bad.as_bytes()))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(rejected).await["error"],
        "idempotency key too long"
    );
    assert_eq!(
        pending_count(&storage).await,
        1,
        "被拒绝请求不得新增 pending"
    );
}

#[tokio::test]
async fn blank_and_non_utf8_keys_are_still_treated_as_missing() {
    let (router, storage, token) = setup("limit-blank.sqlite").await;
    let identity = NodeIdentity::generate("limit-blank");
    let body = signed_key_tx_body("register", &identity, "node");

    let keys: [&[u8]; 3] = [b"   ", b"\t", &[0xff, 0xfe]];
    let mut ids = Vec::new();
    for key in keys {
        let resp = router
            .clone()
            .oneshot(keyed_request(&token, &body, key))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "{:?} 应视为未提供",
            key
        );
        ids.push(body_json(resp).await["data"]["transaction_id"].clone());
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(ids[0], ids[2]);
    assert_eq!(pending_count(&storage).await, 3, "未提供键时每次生成新事务");
}

#[tokio::test]
async fn multibyte_key_is_measured_in_bytes_not_characters() {
    let (router, storage, token) = setup("limit-multibyte.sqlite").await;
    let identity = NodeIdentity::generate("limit-multibyte");
    let body = signed_key_tx_body("register", &identity, "node");
    // 100 个字符 × 3 字节 = 300 字节 > 255。
    let key = "中".repeat(100);
    assert_eq!(key.len(), 300);

    let rejected = router
        .oneshot(keyed_request(&token, &body, key.as_bytes()))
        .await
        .unwrap();
    assert_eq!(
        rejected.status(),
        StatusCode::BAD_REQUEST,
        "长度按字节计:300 字节必须拒绝"
    );
    assert_eq!(
        body_json(rejected).await["error"],
        "idempotency key too long"
    );
    assert_eq!(pending_count(&storage).await, 0);
}
