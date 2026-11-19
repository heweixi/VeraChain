//! B18:身份交易的 `transaction_id` 只是 SQLite 账本 sidecar,不进入区块。
//!
//! 特征测试(针对现有行为,不改 src/):
//! - 区块 JSON(HTTP `GET /api/v1/blocks/:index` 与 `Storage::get_all_blocks`)不含
//!   `transaction_id` 字段,也不含其值;
//! - 区块里 `KeyTransactionEntry::signing_payload()` 只由 5 个签名字段决定,
//!   与是否带 `Idempotency-Key` 无关;
//! - `merkle_root` 不受 `transaction_id` 与服务端盖章的 `timestamp` 影响:同一请求体
//!   在两个独立 state 中分别以"带键"和"不带键"提交,挖出的区块 `merkle_root` 相同。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, EventBus, NotificationService, WsHub};
use datachain::auth::{create_auth_service, RegisterRequest, Role};
use datachain::core::{create_chain, Block, KeyTransactionEntry};
use datachain::crosschain::AnchorService;
use datachain::metadata::create_metadata_manager;
use datachain::node_signing::NodeIdentity;
use datachain::storage::create_storage;

const JWT_SECRET: &str = "integration-test-secret-key-0123456789-abcdef";
const KEY_URI: &str = "/api/v1/identity/key-transaction";

/// 构建完整 AppState(沿用 identity_idempotency_key_limit.rs 的建法)。
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

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).expect("响应体必须是 UTF-8")
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

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
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

/// 由请求体的 5 个签名字段重建 probe 条目;signature/timestamp/reason 置空,
/// 因为它们不参与 `signing_payload()` 与 `leaf_hash()`。
fn probe_from_body(body: &Value) -> KeyTransactionEntry {
    let field = |name: &str| body[name].as_str().unwrap().to_string();
    KeyTransactionEntry {
        tx_type: field("tx_type"),
        target_key: field("target_key"),
        role: field("role"),
        label: field("label"),
        signed_by: field("signed_by"),
        signature: String::new(),
        timestamp: 0,
        reason: String::new(),
    }
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

/// 提交一条密钥交易,返回响应里的 transaction_id。`key` 为 None 时不带 Idempotency-Key。
async fn submit(router: &axum::Router, token: &str, body: &Value, key: Option<&[u8]>) -> String {
    let request = match key {
        Some(k) => keyed_request(token, body, k),
        None => post(KEY_URI, Some(token), body.clone()),
    };
    let resp = router.clone().oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED, "提交密钥交易应被接受");
    let transaction_id = body_json(resp).await["data"]["transaction_id"]
        .as_str()
        .expect("响应必须包含 transaction_id")
        .to_string();
    assert!(!transaction_id.is_empty());
    transaction_id
}

/// 挖矿并返回响应中的区块。
async fn mine(router: &axum::Router, token: &str) -> Block {
    let resp = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(token), Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "挖矿应成功");
    serde_json::from_value(body_json(resp).await["data"].clone()).expect("挖矿响应应是区块")
}

async fn assert_chain_valid(router: &axum::Router, token: &str) {
    let resp = router
        .clone()
        .oneshot(post("/api/v1/chain/validate", Some(token), Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["data"]["valid"], true, "链校验(含 merkle_root)必须通过");
}

#[tokio::test]
async fn transaction_id_absent_from_http_block_and_stored_blocks() {
    let (router, storage, token) = setup("txid-absent.sqlite").await;
    let identity = NodeIdentity::generate("txid-absent");
    let body = signed_key_tx_body("register", &identity, "node");

    let transaction_id = submit(&router, &token, &body, Some(b"txid-absent-key")).await;
    let block = mine(&router, &token).await;
    assert_eq!(block.key_transactions.len(), 1, "该区块应恰含本次密钥交易");

    // HTTP 读区块:原始响应体字符串里既无字段名也无值。
    let resp = router
        .clone()
        .oneshot(get(&format!("/api/v1/blocks/{}", block.index), &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp).await;
    assert!(
        text.contains(&identity.public_key_base64()),
        "前置条件:响应体应确实包含该密钥交易"
    );
    assert!(
        !text.contains(&transaction_id),
        "区块响应不得包含 transaction_id 的值"
    );
    assert!(
        !text.contains("transaction_id"),
        "区块响应不得包含 transaction_id 字段"
    );

    // 持久化区块:序列化后同样不含。
    let stored = storage.get_all_blocks().await.unwrap();
    assert_eq!(stored.len(), 2, "应为创世块 + 本次挖出的区块");
    let stored_json = serde_json::to_string(&stored).unwrap();
    assert!(stored_json.contains(&identity.public_key_base64()));
    assert!(
        !stored_json.contains(&transaction_id),
        "持久化区块不得包含 transaction_id 的值"
    );
    assert!(
        !stored_json.contains("transaction_id"),
        "持久化区块不得包含 transaction_id 字段"
    );
}

#[tokio::test]
async fn signing_payload_depends_only_on_five_signed_fields_with_or_without_key() {
    let (router, _storage, token) = setup("txid-payload.sqlite").await;
    let keyed_identity = NodeIdentity::generate("txid-payload-keyed");
    let plain_identity = NodeIdentity::generate("txid-payload-plain");
    let keyed_body = signed_key_tx_body("register", &keyed_identity, "node");
    let plain_body = signed_key_tx_body("register", &plain_identity, "node");

    submit(&router, &token, &keyed_body, Some(b"txid-payload-key")).await;
    submit(&router, &token, &plain_body, None).await;
    let block = mine(&router, &token).await;
    assert_eq!(block.key_transactions.len(), 2);

    // 按提交顺序入块:[0] 带键,[1] 不带键。
    for (entry, body) in block.key_transactions.iter().zip([&keyed_body, &plain_body]) {
        let probe = probe_from_body(body);
        assert_eq!(
            entry.signing_payload(),
            probe.signing_payload(),
            "区块条目的 signing_payload 只能由 5 个签名字段决定"
        );
        assert_eq!(entry.leaf_hash(), probe.leaf_hash());
        let expected = format!(
            "register|{pk}|node|node-a|{pk}",
            pk = body["target_key"].as_str().unwrap()
        );
        assert_eq!(entry.signing_payload(), expected.into_bytes());
        assert_eq!(entry.signature, body["signature"].as_str().unwrap());
    }
    assert_chain_valid(&router, &token).await;
}

#[tokio::test]
async fn merkle_root_is_identical_with_or_without_idempotency_key() {
    // 两个独立 state 是本用例的前提:同一密钥不能在同一链上重复注册比较。
    let identity = NodeIdentity::generate("txid-merkle");
    let body = signed_key_tx_body("register", &identity, "node");
    let probe = probe_from_body(&body);

    let (keyed_router, _keyed_storage, keyed_token) = setup("txid-merkle-keyed.sqlite").await;
    submit(&keyed_router, &keyed_token, &body, Some(b"txid-merkle-key")).await;
    let keyed_block = mine(&keyed_router, &keyed_token).await;
    assert_chain_valid(&keyed_router, &keyed_token).await;

    let (plain_router, _plain_storage, plain_token) = setup("txid-merkle-plain.sqlite").await;
    submit(&plain_router, &plain_token, &body, None).await;
    let plain_block = mine(&plain_router, &plain_token).await;
    assert_chain_valid(&plain_router, &plain_token).await;

    assert_eq!(keyed_block.key_transactions.len(), 1);
    assert_eq!(plain_block.key_transactions.len(), 1);
    assert!(!keyed_block.merkle_root.is_empty());
    assert_eq!(
        keyed_block.merkle_root, plain_block.merkle_root,
        "merkle_root 不得受 transaction_id / Idempotency-Key 影响"
    );
    // 单叶子:merkle_root 等于由 5 字段构造的 probe 叶子哈希(timestamp 不参与)。
    assert_eq!(keyed_block.merkle_root, probe.leaf_hash());
    assert_eq!(keyed_block.merkle_root, keyed_block.calculate_merkle_root());
}
