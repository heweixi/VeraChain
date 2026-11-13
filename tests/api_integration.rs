//! API 集成测试:在进程内用 tower oneshot 驱动真实 Router,覆盖认证、RBAC 越权、
//! 端到端业务流(注册→登录→元数据→挖矿→跨链锚定)与 SQLite 重启恢复。
//!
//! 不走网络;P2P 双节点广播/发现路径已由 247 双容器 smoke 验证(见 R6 commit)。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, EventBus, NotificationService, WsHub};
use datachain::auth::{create_auth_service, RegisterRequest, Role};
use datachain::catalog::{Artifact, CatalogPayload, CatalogRecord, Claim, Revision, Subject};
use datachain::config::{ClaimPolicyConfig, TrustedIssuerConfig};
use datachain::core::{create_chain, KeyTransactionEntry};
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
    datachain::cli::server::recover_pending_identity_transactions(&chain, &storage)
        .await
        .unwrap();

    let auth_service = create_auth_service(JWT_SECRET.to_string(), 24, storage.clone());
    for user in storage.get_all_users().await.unwrap() {
        auth_service.load_user(user);
    }

    let metadata_manager = create_metadata_manager(chain.clone(), storage.clone());
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
        claim_resolver: Arc::new(datachain::catalog::ClaimResolver::new(Default::default())),
        identity_tx_gate: Arc::new(tokio::sync::Mutex::new(())),
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
async fn chain_validation_api_reports_validity_and_requires_block_read_token() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "reader", "readerpass123", Role::User).await;
    let router = api::create_router(state.clone());
    let token = login(router.clone(), "reader", "readerpass123").await;

    let response = router
        .clone()
        .oneshot(post("/api/v1/chain/validate", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["valid"], true);

    let mut corrupt_blocks = state.chain.get_all_blocks();
    corrupt_blocks[0].previous_hash = "tampered-genesis-parent".to_string();
    corrupt_blocks[0].mine();
    state.chain.load_blocks(corrupt_blocks);
    let response = router
        .clone()
        .oneshot(post("/api/v1/chain/validate", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["valid"], false);

    let response = router
        .oneshot(post("/api/v1/chain/validate", None, Value::Null))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

// ---------------------------------------------------------------------------
// 跨链认证网 L1:链上身份端到端(注册→挖矿→查询→撤销→查询 + RBAC + 验签)
// ---------------------------------------------------------------------------

/// 用给定身份对规范化负载签名,构造 key-transaction 请求体。
/// 规范化负载必须与服务端 `KeyTransactionEntry::signing_payload` 一致(不含 timestamp)。
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

#[tokio::test]
async fn identity_register_mine_query_revoke_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;

    let id = NodeIdentity::generate("node-a");
    let pk = id.public_key_base64();

    // 1) 提交 register key-transaction(自签),应被接受(202)。
    let resp = router
        .clone()
        .oneshot(post(
            "/api/v1/identity/key-transaction",
            Some(&token),
            signed_key_tx_body("register", &id, "node"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "合法自签 register 应被接受"
    );

    // 2) 挖矿把 key-tx 打包进区块。
    let resp = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let mined = body_json(resp).await;
    // 区块应带非空 identity_snapshot_hash(当前有有效密钥)。
    assert!(
        mined["data"]["identity_snapshot_hash"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "挖矿后应写入非空 identity_snapshot_hash"
    );

    // 3) GET /identity/keys 应出现该公钥且 active。
    let resp = router
        .clone()
        .oneshot(get("/api/v1/identity/keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let keys = body_json(resp).await;
    let arr = keys["data"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "应有一个有效密钥");
    assert_eq!(arr[0]["public_key"], pk);
    assert_eq!(arr[0]["status"], "active");

    // 单个查询命中。
    let resp = router
        .clone()
        .oneshot(get(
            &format!("/api/v1/identity/keys/{}", urlencoding(&pk)),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4) 提交 revoke(自签)→ 挖矿 → GET /keys 应为空。
    let resp = router
        .clone()
        .oneshot(post(
            "/api/v1/identity/key-transaction",
            Some(&token),
            signed_key_tx_body("revoke", &id, "node"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = router
        .clone()
        .oneshot(get("/api/v1/identity/keys", Some(&token)))
        .await
        .unwrap();
    let keys = body_json(resp).await;
    assert_eq!(
        keys["data"].as_array().unwrap().len(),
        0,
        "revoke 挖矿后有效密钥集应为空"
    );
}

#[tokio::test]
async fn identity_invalid_signature_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;

    let id = NodeIdentity::generate("node-a");
    let mut body = signed_key_tx_body("register", &id, "node");
    body["signature"] = Value::String("AAAAinvalidsig".to_string());

    let resp = router
        .oneshot(post("/api/v1/identity/key-transaction", Some(&token), body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "无效签名应被拒(400)"
    );
}

#[tokio::test]
async fn identity_key_tx_requires_blockmine_permission() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    seed_user(&state, "guest", "guestpass123", Role::Guest).await;
    let router = api::create_router(state);
    let guest_token = login(router.clone(), "guest", "guestpass123").await;

    let id = NodeIdentity::generate("node-a");
    // guest 无 BlockMine 权限,提交 key-tx 应 403(被 RBAC 中间件拦在验签之前)。
    let resp = router
        .oneshot(post(
            "/api/v1/identity/key-transaction",
            Some(&guest_token),
            signed_key_tx_body("register", &id, "node"),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "guest 提交 key-tx 应 403"
    );
}

/// 最小 URL 编码:base64 公钥可能含 '/' '+' '=',路径段需编码。
fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 可验证语义目录：Subject → Revision → Artifact + 带证据 Claim
// ---------------------------------------------------------------------------

fn signed_catalog_body(payload: CatalogPayload, issuer: &NodeIdentity) -> Value {
    let issuer_key = issuer.public_key_base64();
    let issuer_identity = "issuer:node-a";
    let signature = issuer.sign_base64(&CatalogRecord::request_signing_payload(
        &payload,
        issuer_identity,
        &issuer_key,
    ));
    serde_json::json!({
        "payload": serde_json::to_value(payload).unwrap(),
        "issuer_identity": issuer_identity,
        "issuer_key": issuer_key,
        "signature": signature,
    })
}

async fn mine_catalog_record(router: axum::Router, token: &str) {
    let response = router
        .oneshot(post("/api/v1/chain/mine", Some(token), Value::Null))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn catalog_subject_revision_artifact_claim_are_signed_committed_and_queryable() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("catalog.sqlite");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let admin_token = login(router.clone(), "admin", "adminpass123").await;

    // 认证者必须先成为已上链的有效身份，才可签发目录记录或 Claim。
    let issuer = NodeIdentity::generate("catalog-issuer");
    let identity_response = router
        .clone()
        .oneshot(post(
            "/api/v1/identity/key-transaction",
            Some(&admin_token),
            signed_key_tx_body("register", &issuer, "auditor"),
        ))
        .await
        .unwrap();
    assert_eq!(identity_response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &admin_token).await;

    let subject = CatalogPayload::Subject(Subject {
        subject_id: "repo-example".to_string(),
        subject_type: "repository".to_string(),
        display_name: "Example Repository".to_string(),
        source_ref: "https://example.invalid/repo".to_string(),
    });
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&admin_token),
            signed_catalog_body(subject, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &admin_token).await;

    let response = router
        .clone()
        .oneshot(get(
            "/api/v1/catalog/subjects/repo-example",
            Some(&admin_token),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let subject_response = body_json(response).await;
    assert_eq!(subject_response["data"]["payload"]["type"], "subject");
    assert_eq!(
        subject_response["data"]["payload"]["subject_id"],
        "repo-example"
    );

    let revision = CatalogPayload::Revision(Revision {
        revision_id: "repo-example-v1".to_string(),
        subject_id: "repo-example".to_string(),
        content_hash: "sha256:source-v1".to_string(),
        parent_revision_id: String::new(),
        source_ref: "refs/tags/v1.0.0".to_string(),
    });
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&admin_token),
            signed_catalog_body(revision, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &admin_token).await;

    let artifact = CatalogPayload::Artifact(Artifact {
        artifact_id: "repo-example-v1-linux".to_string(),
        revision_id: "repo-example-v1".to_string(),
        artifact_hash: "sha256:artifact-linux".to_string(),
        configuration_hash: "sha256:release-config".to_string(),
        platform: "linux-x86_64".to_string(),
    });
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&admin_token),
            signed_catalog_body(artifact, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &admin_token).await;

    let claim = CatalogPayload::Claim(Claim {
        claim_id: "claim-example-v1-risk".to_string(),
        subject_id: "repo-example".to_string(),
        revision_id: "repo-example-v1".to_string(),
        artifact_id: "repo-example-v1-linux".to_string(),
        category: "risk.vulnerability".to_string(),
        status: "confirmed".to_string(),
        evidence_ref: "sha256:security-report-v1".to_string(),
        observed_at: 1_700_000_000,
        effective_from: Some(1_700_000_000),
        effective_to: None,
        supersedes_claim_id: String::new(),
    });
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&admin_token),
            signed_catalog_body(claim, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &admin_token).await;

    let revisions = router
        .clone()
        .oneshot(get(
            "/api/v1/catalog/subjects/repo-example/revisions",
            Some(&admin_token),
        ))
        .await
        .unwrap();
    let revisions = body_json(revisions).await;
    assert_eq!(revisions["data"].as_array().unwrap().len(), 1);

    let artifacts = router
        .clone()
        .oneshot(get(
            "/api/v1/catalog/revisions/repo-example-v1/artifacts",
            Some(&admin_token),
        ))
        .await
        .unwrap();
    let artifacts = body_json(artifacts).await;
    assert_eq!(artifacts["data"].as_array().unwrap().len(), 1);

    let claims = router
        .oneshot(get(
            "/api/v1/catalog/subjects/repo-example/claims",
            Some(&admin_token),
        ))
        .await
        .unwrap();
    let claims = body_json(claims).await;
    assert_eq!(claims["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        claims["data"][0]["payload"]["category"],
        "risk.vulnerability"
    );
}

#[tokio::test]
async fn catalog_rejects_unknown_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("catalog-invalid.sqlite");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let issuer = NodeIdentity::generate("unregistered-issuer");

    let subject = CatalogPayload::Subject(Subject {
        subject_id: "blocked-subject".to_string(),
        subject_type: "article".to_string(),
        display_name: "Blocked Subject".to_string(),
        source_ref: String::new(),
    });
    // 数学签名有效，但公钥尚未登记为链上身份，必须拒绝。
    let response = router
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&token),
            signed_catalog_body(subject, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn effective_claims_api_applies_trusted_issuer_policy() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("catalog-policy.sqlite");
    let (mut state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;

    let issuer = NodeIdentity::generate("policy-issuer");
    let issuer_key = issuer.public_key_base64();
    state.claim_resolver = Arc::new(datachain::catalog::ClaimResolver::new(ClaimPolicyConfig {
        min_weight: 5,
        trusted_issuers: vec![TrustedIssuerConfig {
            issuer_identity: "issuer:node-a".to_string(),
            issuer_key,
            weight: 10,
            categories: vec!["risk.*".to_string()],
        }],
    }));
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;

    // 先登记认证者身份与目标对象。
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/identity/key-transaction",
            Some(&token),
            signed_key_tx_body("register", &issuer, "auditor"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &token).await;

    let subject = CatalogPayload::Subject(Subject {
        subject_id: "policy-subject".to_string(),
        subject_type: "package".to_string(),
        display_name: "Policy Subject".to_string(),
        source_ref: String::new(),
    });
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&token),
            signed_catalog_body(subject, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &token).await;

    let claim = CatalogPayload::Claim(Claim {
        claim_id: "policy-risk".to_string(),
        subject_id: "policy-subject".to_string(),
        revision_id: String::new(),
        artifact_id: String::new(),
        category: "risk.vulnerability".to_string(),
        status: "confirmed".to_string(),
        evidence_ref: "sha256:policy-report".to_string(),
        observed_at: 1,
        effective_from: Some(1),
        effective_to: None,
        supersedes_claim_id: String::new(),
    });
    let response = router
        .clone()
        .oneshot(post(
            "/api/v1/catalog/records",
            Some(&token),
            signed_catalog_body(claim, &issuer),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    mine_catalog_record(router.clone(), &token).await;

    let response = router
        .oneshot(get(
            "/api/v1/catalog/subjects/policy-subject/effective-claims?as_of=2",
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response).await;
    assert_eq!(
        result["data"]["effective_claims"].as_array().unwrap().len(),
        1
    );
    assert!(result["data"]["conflicts"].as_array().unwrap().is_empty());
    assert_eq!(
        result["data"]["effective_claims"][0]["claim"]["claim_id"],
        "policy-risk"
    );
}

#[tokio::test]
async fn identity_key_transaction_idempotency_key_replays_pending_then_committed() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let id = NodeIdentity::generate("idempotency-node");
    let body = signed_key_tx_body("register", &id, "node");

    let request = |body: Value| {
        let mut request = post("/api/v1/identity/key-transaction", Some(&token), body);
        request
            .headers_mut()
            .insert("idempotency-key", "identity-retry-1".parse().unwrap());
        request
    };

    let first = router.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first_body = body_json(first).await;
    let transaction_id = first_body["data"]["transaction_id"]
        .as_str()
        .expect("首次 pending 响应必须包含 transaction_id")
        .to_string();

    let replay = router.clone().oneshot(request(body.clone())).await.unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        body_json(replay).await["data"]["transaction_id"],
        transaction_id
    );

    let mined = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(mined.status(), StatusCode::CREATED);

    let committed = router.oneshot(request(body)).await.unwrap();
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(body_json(committed).await["data"]["status"], "committed");
}

#[tokio::test]
async fn identity_key_transaction_idempotency_ignores_unsigned_reason() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let identity = NodeIdentity::generate("idempotency-reason");
    let body = signed_key_tx_body("register", &identity, "node");
    let mut body_with_different_reason = body.clone();
    body_with_different_reason["reason"] = Value::String("retry context".to_string());

    let request = |body: Value| {
        let mut request = post("/api/v1/identity/key-transaction", Some(&token), body);
        request
            .headers_mut()
            .insert("idempotency-key", "identity-reason-1".parse().unwrap());
        request
    };

    let first = router.clone().oneshot(request(body)).await.unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let transaction_id = body_json(first).await["data"]["transaction_id"]
        .as_str()
        .expect("首次 pending 响应必须包含 transaction_id")
        .to_string();

    let replay = router
        .oneshot(request(body_with_different_reason))
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::ACCEPTED,
        "仅未签名 reason 不同的重试应复用原交易"
    );
    assert_eq!(
        body_json(replay).await["data"]["transaction_id"],
        transaction_id,
        "同一已签名规范化负载必须复用同一 transaction_id"
    );
}

#[tokio::test]
async fn identity_key_transaction_reused_key_with_different_request_returns_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let first_identity = NodeIdentity::generate("first-identity");
    let second_identity = NodeIdentity::generate("second-identity");

    let keyed_request = |body: Value| {
        let mut request = post("/api/v1/identity/key-transaction", Some(&token), body);
        request
            .headers_mut()
            .insert("idempotency-key", "identity-conflict-1".parse().unwrap());
        request
    };

    let first = router
        .clone()
        .oneshot(keyed_request(signed_key_tx_body(
            "register",
            &first_identity,
            "node",
        )))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let conflict = router
        .clone()
        .oneshot(keyed_request(signed_key_tx_body(
            "register",
            &second_identity,
            "node",
        )))
        .await
        .unwrap();
    assert_eq!(
        conflict.status(),
        StatusCode::CONFLICT,
        "同一认证用户不得以相同 Idempotency-Key 提交不同签名请求"
    );

    let mined = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(mined.status(), StatusCode::CREATED);

    let keys = router
        .oneshot(get("/api/v1/identity/keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(keys.status(), StatusCode::OK);
    let keys = body_json(keys).await;
    let keys = keys["data"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "冲突请求不得进入待打包队列");
    assert_eq!(keys[0]["public_key"], first_identity.public_key_base64());
}

#[tokio::test]
async fn identity_key_transaction_without_idempotency_key_retains_accepted_pending_behavior() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let identity = NodeIdentity::generate("no-key-identity");
    let body = signed_key_tx_body("register", &identity, "node");

    let first = router
        .clone()
        .oneshot(post(
            "/api/v1/identity/key-transaction",
            Some(&token),
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first_body = body_json(first).await;

    let second = router
        .clone()
        .oneshot(post("/api/v1/identity/key-transaction", Some(&token), body))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    let second_body = body_json(second).await;
    assert_ne!(
        first_body["data"]["transaction_id"], second_body["data"]["transaction_id"],
        "无 Idempotency-Key 的兼容路径不提供去重保证"
    );

    let mined = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(mined.status(), StatusCode::CREATED);
    let keys = router
        .oneshot(get("/api/v1/identity/keys", Some(&token)))
        .await
        .unwrap();
    let keys = body_json(keys).await;
    assert_eq!(keys["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn identity_key_transaction_concurrent_same_key_creates_one_pending_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let identity = NodeIdentity::generate("concurrent-identity");
    let body = signed_key_tx_body("register", &identity, "node");

    let keyed_request = |body: Value| {
        let mut request = post("/api/v1/identity/key-transaction", Some(&token), body);
        request
            .headers_mut()
            .insert("idempotency-key", "identity-concurrent-1".parse().unwrap());
        request
    };
    let (first, second) = tokio::join!(
        router.clone().oneshot(keyed_request(body.clone())),
        router.clone().oneshot(keyed_request(body)),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_eq!(
        body_json(first).await["data"]["transaction_id"],
        body_json(second).await["data"]["transaction_id"],
        "并发同 key 必须收敛到同一 pending 账本交易"
    );

    let mined = router
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(mined.status(), StatusCode::CREATED);
    let mined = body_json(mined).await;
    assert_eq!(
        mined["data"]["key_transactions"].as_array().unwrap().len(),
        1,
        "同 key 并发重试不得产生第二条已入块身份交易"
    );
}

#[tokio::test]
async fn identity_key_transaction_restart_recovers_pending_for_mining() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let dsn = dsn.to_str().unwrap();
    let identity = NodeIdentity::generate("restart-identity");
    let body = signed_key_tx_body("register", &identity, "node");

    {
        let (state, _) = build_state(dsn).await;
        seed_user(&state, "admin", "adminpass123", Role::Admin).await;
        let router = api::create_router(state);
        let token = login(router.clone(), "admin", "adminpass123").await;
        let response = router
            .oneshot(post(
                "/api/v1/identity/key-transaction",
                Some(&token),
                body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let (state, _) = build_state(dsn).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let mined = router
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(
        mined.status(),
        StatusCode::CREATED,
        "重启后应恢复持久化 pending 身份交易并允许挖矿"
    );
    let keys = router
        .oneshot(get("/api/v1/identity/keys", Some(&token)))
        .await
        .unwrap();
    assert_eq!(keys.status(), StatusCode::OK);
    let keys = body_json(keys).await;
    assert_eq!(keys["data"].as_array().unwrap().len(), 1);
    assert_eq!(keys["data"][0]["public_key"], identity.public_key_base64());
}

#[tokio::test]
async fn identity_transaction_remains_pending_when_another_app_state_mines_only_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("shared-state.sqlite");
    let dsn = dsn.to_str().unwrap();

    // 两个 AppState 在 t1 被 A 接受之前就已启动，因此 B 的内存队列只应包含它自己接受的条目。
    let (state_a, _) = build_state(dsn).await;
    seed_user(&state_a, "admin", "adminpass123", Role::Admin).await;
    let router_a = api::create_router(state_a);
    let token_a = login(router_a.clone(), "admin", "adminpass123").await;

    let (state_b, _) = build_state(dsn).await;
    let router_b = api::create_router(state_b);
    let token_b = login(router_b.clone(), "admin", "adminpass123").await;

    let identity = NodeIdentity::generate("shared-state-identity");
    let key_body = signed_key_tx_body("register", &identity, "node");
    let keyed_request = |body: Value| {
        let mut request = post("/api/v1/identity/key-transaction", Some(&token_a), body);
        request
            .headers_mut()
            .insert("idempotency-key", "shared-state-t1".parse().unwrap());
        request
    };

    let accepted = router_a
        .clone()
        .oneshot(keyed_request(key_body.clone()))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let transaction_id = body_json(accepted).await["data"]["transaction_id"]
        .as_str()
        .unwrap()
        .to_string();

    let metadata = router_b
        .clone()
        .oneshot(post(
            "/api/v1/metadata",
            Some(&token_b),
            serde_json::json!({"data_size":1,"owner":"admin","hashes":{"sha256":"metadata"},"metadata":{},"tags":[]}),
        ))
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::CREATED);

    let mined_by_b = router_b
        .clone()
        .oneshot(post("/api/v1/chain/mine", Some(&token_b), Value::Null))
        .await
        .unwrap();
    assert_eq!(mined_by_b.status(), StatusCode::CREATED);
    let mined_by_b = body_json(mined_by_b).await;
    assert!(
        mined_by_b["data"]["key_transactions"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "B 的区块不得包含仅在 A 内存队列中的 t1"
    );

    let still_pending = router_a
        .clone()
        .oneshot(keyed_request(key_body.clone()))
        .await
        .unwrap();
    assert_eq!(still_pending.status(), StatusCode::ACCEPTED);
    let still_pending = body_json(still_pending).await;
    assert_eq!(still_pending["data"]["transaction_id"], transaction_id);
    assert_eq!(still_pending["data"]["status"], "pending");

    // 模拟 A 重启：从账本恢复 t1 后，它应只被打包一次。
    drop(router_a);
    drop(router_b);
    let (restarted_a, _) = build_state(dsn).await;
    let restarted_router = api::create_router(restarted_a);
    let restarted_token = login(restarted_router.clone(), "admin", "adminpass123").await;
    let mined_by_restarted_a = restarted_router
        .clone()
        .oneshot(post(
            "/api/v1/chain/mine",
            Some(&restarted_token),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(mined_by_restarted_a.status(), StatusCode::CREATED);
    let mined_by_restarted_a = body_json(mined_by_restarted_a).await;
    let key_transactions = mined_by_restarted_a["data"]["key_transactions"]
        .as_array()
        .unwrap();
    assert_eq!(key_transactions.len(), 1, "重启后 t1 应恰好入块一次");
    assert_eq!(
        key_transactions[0]["target_key"],
        identity.public_key_base64()
    );

    let committed = restarted_router
        .oneshot(keyed_request(key_body))
        .await
        .unwrap();
    assert_eq!(committed.status(), StatusCode::OK);
    assert_eq!(body_json(committed).await["data"]["status"], "committed");
}

#[tokio::test]
async fn idempotency_key_is_scoped_to_user_and_blank_values_do_not_deduplicate() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("idempotency-scope.sqlite");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::Admin).await;
    seed_user(&state, "bob", "bobpass123456", Role::Admin).await;
    let router = api::create_router(state);
    let alice_token = login(router.clone(), "alice", "alicepass123").await;
    let bob_token = login(router.clone(), "bob", "bobpass123456").await;
    let identity = NodeIdentity::generate("idempotency-scope");
    let body = signed_key_tx_body("register", &identity, "node");

    let keyed_request = |token: &str, key: &str| {
        let mut request = post(
            "/api/v1/identity/key-transaction",
            Some(token),
            body.clone(),
        );
        request
            .headers_mut()
            .insert("idempotency-key", key.parse().unwrap());
        request
    };

    let alice = router
        .clone()
        .oneshot(keyed_request(&alice_token, "same-key"))
        .await
        .unwrap();
    let bob = router
        .clone()
        .oneshot(keyed_request(&bob_token, "same-key"))
        .await
        .unwrap();
    assert_eq!(alice.status(), StatusCode::ACCEPTED);
    assert_eq!(bob.status(), StatusCode::ACCEPTED);
    assert_ne!(
        body_json(alice).await["data"]["transaction_id"],
        body_json(bob).await["data"]["transaction_id"],
        "不同用户可独立使用相同 Idempotency-Key"
    );

    let blank_first = router
        .clone()
        .oneshot(keyed_request(&alice_token, "   "))
        .await
        .unwrap();
    let blank_second = router
        .oneshot(keyed_request(&alice_token, "\t"))
        .await
        .unwrap();
    assert_eq!(blank_first.status(), StatusCode::ACCEPTED);
    assert_eq!(blank_second.status(), StatusCode::ACCEPTED);
    assert_ne!(
        body_json(blank_first).await["data"]["transaction_id"],
        body_json(blank_second).await["data"]["transaction_id"],
        "空白 Idempotency-Key 应视为未提供"
    );
}

#[tokio::test]
async fn non_ascii_idempotency_key_is_treated_as_missing_and_cors_preflight_allows_the_header() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("idempotency-header.sqlite");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let identity = NodeIdentity::generate("idempotency-header");
    let body = signed_key_tx_body("register", &identity, "node");

    let non_ascii_request = || {
        let mut request = post(
            "/api/v1/identity/key-transaction",
            Some(&token),
            body.clone(),
        );
        request.headers_mut().insert(
            "idempotency-key",
            HeaderValue::from_bytes(&[0xff]).expect("obs-text 是合法 HTTP header value"),
        );
        request
    };
    let first = router.clone().oneshot(non_ascii_request()).await.unwrap();
    let second = router.clone().oneshot(non_ascii_request()).await.unwrap();
    assert_eq!(
        first.status(),
        StatusCode::ACCEPTED,
        "非 ASCII Idempotency-Key 应视为未提供并正常接受"
    );
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    assert_ne!(
        body_json(first).await["data"]["transaction_id"],
        body_json(second).await["data"]["transaction_id"],
        "非 ASCII Idempotency-Key 不得触发幂等去重"
    );

    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/identity/key-transaction")
        .header("origin", "http://localhost:3000")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization,content-type,idempotency-key",
        )
        .body(Body::empty())
        .unwrap();
    let preflight = router.oneshot(preflight).await.unwrap();
    assert_eq!(preflight.status(), StatusCode::OK);
    let allowed_headers = preflight
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(allowed_headers
        .to_ascii_lowercase()
        .contains("idempotency-key"));
}

#[tokio::test]
async fn failed_identity_transaction_commit_rolls_back_the_mined_block_and_pending_queue() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("identity-commit-rollback.sqlite");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "admin", "adminpass123", Role::Admin).await;
    let chain = state.chain.clone();
    let router = api::create_router(state);
    let token = login(router.clone(), "admin", "adminpass123").await;
    let identity = NodeIdentity::generate("identity-commit-rollback");
    let body = signed_key_tx_body("register", &identity, "node");
    let mut request = post("/api/v1/identity/key-transaction", Some(&token), body);
    request
        .headers_mut()
        .insert("idempotency-key", "rollback-t1".parse().unwrap());
    let accepted = router.clone().oneshot(request).await.unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let transaction_id = body_json(accepted).await["data"]["transaction_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 用公开 Storage API 将账本行抢先转换为 committed，构造 handler 的原子提交失败点。
    // sidecar 必须与区块内条目配对，才能模拟另一实例合法完成的提交。
    let transaction = storage
        .get_identity_transaction(&transaction_id)
        .await
        .unwrap()
        .unwrap();
    let mut conflicting_block = datachain::core::Block::new(99, "0".repeat(64), 1);
    conflicting_block.key_transactions.push(transaction.entry);
    conflicting_block.hash = "external-commit".to_string();
    storage
        .commit_block(&conflicting_block, &[Some(transaction_id)])
        .await
        .unwrap();

    let failed_mine = router
        .oneshot(post("/api/v1/chain/mine", Some(&token), Value::Null))
        .await
        .unwrap();
    assert_eq!(failed_mine.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(chain.get_block_count(), 1, "失败不得留下内存区块");
    assert_eq!(
        chain.get_pending_key_tx_count(),
        1,
        "失败后 identity pending 队列必须恢复"
    );
}
