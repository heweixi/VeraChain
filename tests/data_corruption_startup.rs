//! S4:启动时序 + HTTP `/chain/validate`。
//!
//! Red 基线(实施前):
//! - `scan_authoritative_sources_and_ensure_projections` 不存在,server.rs 的启动
//!   顺序是"先去重/回填,后(其实从未)扫描权威源",损坏的 users 行不会在去重/回填
//!   之前被发现,也不存在 fail-closed 中止点。
//! - handlers::validate_chain 返回体不含 corruption/invalid_block 字段。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, EventBus, NotificationService, WsHub};
use datachain::auth::create_auth_service;
use datachain::core::create_chain;
use datachain::crosschain::AnchorService;
use datachain::metadata::create_metadata_manager;
use datachain::node_signing::NodeIdentity;
use datachain::storage::create_storage;

mod common;

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn post(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

/// `/chain/validate` 是受保护路由:在内存认证服务中注册只读用户并签发合法 token。
/// token 不依赖 blocks/users 表,可在损坏数据之前或之后获取。
async fn reader_token(state: &AppState) -> String {
    use datachain::auth::{LoginContext, LoginRequest, RegisterRequest, Role};
    let req = RegisterRequest {
        username: "reader".to_string(),
        password: "readerpass123".to_string(),
        email: "reader@test.local".to_string(),
        role: Some(Role::User),
    };
    let user = state
        .auth_service
        .register_with_role(&req, Role::User)
        .unwrap();
    // 认证加固后 access token 绑定会话且用户启用状态以 SQLite 为权威,用户需先落库。
    state.storage.save_user(&user).await.unwrap();
    state
        .auth_service
        .login(
            &LoginRequest {
                username: "reader".to_string(),
                password: "readerpass123".to_string(),
            },
            &LoginContext::default(),
        )
        .await
        .unwrap()
        .token
}

async fn build_state(dsn: &str) -> AppState {
    let storage = create_storage(dsn).await.unwrap();
    let chain = create_chain(1, 100);
    let blocks = storage.get_all_blocks().await.unwrap();
    if blocks.is_empty() {
        let genesis = chain.init();
        storage.save_block(&genesis).await.unwrap();
    } else {
        chain.load_blocks(blocks);
    }

    let auth_service = create_auth_service(
        "test-secret-0123456789abcdef".to_string(),
        24,
        storage.clone(),
    );
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

    AppState {
        chain,
        auth_service,
        metadata_manager,
        version_tracker,
        aggregation_engine,
        storage,
        ws_hub,
        event_bus,
        scheduler,
        p2p,
        rate_limiter,
        anchor_service,
        claim_resolver: Arc::new(datachain::catalog::ClaimResolver::new(Default::default())),
        identity_tx_gate: Arc::new(tokio::sync::Mutex::new(())),
    }
}

#[tokio::test]
async fn chain_validate_http_reports_corruption_without_leaking_sensitive_fields() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let dsn_str = dsn.to_str().unwrap();

    let state = build_state(dsn_str).await;
    let token = reader_token(&state).await;
    // 用底层接口写一个 users 行,再直接改坏其 metadata 列。
    let user = datachain::auth::User::new(
        "tester".to_string(),
        "SECRET-XYZ".to_string(),
        "tester@example.com".to_string(),
        datachain::auth::Role::User,
    );
    state.storage.save_user(&user).await.unwrap();
    let pool = common::corrupt::connect(dsn_str).await;
    common::corrupt::corrupt_user_metadata(&pool, &user.user_id).await;
    pool.close().await;

    // /chain/validate 本身只扫描 blocks(当前实现),用 blocks 损坏来触发该端点的
    // corruption 字段(users 损坏由启动时序独立覆盖,见下一个测试)。
    let corrupt_genesis_pool = common::corrupt::connect(dsn_str).await;
    sqlx::query("UPDATE blocks SET data = '{not valid json' WHERE block_index = 0")
        .execute(&corrupt_genesis_pool)
        .await
        .unwrap();
    corrupt_genesis_pool.close().await;

    let router = api::create_router(state);
    let resp = router
        .oneshot(post("/api/v1/chain/validate", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "损坏时状态码仍保持 200");
    let json = body_json(resp).await;
    let data = &json["data"];
    assert_eq!(data["corruption"]["table"], "blocks");
    assert_eq!(data["corruption"]["category"], "authoritative");

    let body_str = json.to_string();
    assert!(
        !body_str.contains("SECRET-XYZ"),
        "HTTP body 不得泄露 password_hash"
    );
}

#[tokio::test]
async fn chain_validate_http_fields_unchanged_when_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let state = build_state(dsn.to_str().unwrap()).await;
    let token = reader_token(&state).await;
    let router = api::create_router(state);

    let resp = router
        .oneshot(post("/api/v1/chain/validate", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let data = &json["data"];
    assert_eq!(data["valid"], true);
    assert_eq!(data["block_count"], 1);
    assert!(data.get("corruption").is_none() || data["corruption"].is_null());
    assert!(data.get("invalid_block").is_none() || data["invalid_block"].is_null());
}

/// 启动时序:权威源(users)损坏时,`scan_authoritative_sources_and_ensure_projections`
/// 必须 fail-closed,且此时去重/回填尚未执行 —— 用"调用前后 pending_metadata 表
/// 行数不变"来断言未发生写操作(该函数本身不做去重写,写操作在调用方 run_server 里,
/// 这里直接验证 seam 返回 Err 且不改库)。
#[tokio::test]
async fn startup_scan_fails_closed_on_corrupt_users_before_any_projection_or_pending_mutation() {
    use datachain::cli::server::scan_authoritative_sources_and_ensure_projections;

    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let dsn_str = dsn.to_str().unwrap();

    let storage = create_storage(dsn_str).await.unwrap();
    let chain = create_chain(1, 100);
    let genesis = chain.init();
    storage.save_block(&genesis).await.unwrap();

    let user = datachain::auth::User::new(
        "tester".to_string(),
        "SECRET-XYZ".to_string(),
        "tester@example.com".to_string(),
        datachain::auth::Role::User,
    );
    storage.save_user(&user).await.unwrap();
    let pool = common::corrupt::connect(dsn_str).await;
    common::corrupt::corrupt_user_metadata(&pool, &user.user_id).await;
    pool.close().await;

    let metadata_count_before = storage.metadata_projection_count().await.unwrap();

    let result = scan_authoritative_sources_and_ensure_projections(&chain, &storage).await;
    assert!(result.is_err(), "users 损坏必须 fail-closed");
    let message = result.unwrap_err().to_string();
    assert!(message.contains("table=users"));
    assert!(!message.contains("SECRET-XYZ"));

    // 投影表未被写入(ensure_projections 在权威源扫描失败后根本不会被调用到)。
    assert_eq!(
        storage.metadata_projection_count().await.unwrap(),
        metadata_count_before
    );
}

#[tokio::test]
async fn startup_scan_rebuilds_projection_when_only_metadata_table_is_corrupt() {
    use chrono::Utc;
    use datachain::cli::server::scan_authoritative_sources_and_ensure_projections;
    use datachain::core::MetadataEntry;

    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let dsn_str = dsn.to_str().unwrap();

    let storage = create_storage(dsn_str).await.unwrap();
    let chain = create_chain(1, 100);
    let mut genesis = chain.init();
    genesis.metadata_list.push(MetadataEntry {
        data_id: "m1".to_string(),
        data_size: 1,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        owner: "alice".to_string(),
        hashes: std::collections::HashMap::new(),
        metadata: std::collections::HashMap::new(),
        parent_id: None,
        tags: Vec::new(),
    });
    genesis.mine();
    // 直接用 commit_block 写入(保证 metadata 投影同步生成),再替换内存链的创世块。
    storage.commit_block(&genesis, &[]).await.unwrap();
    chain.load_blocks(vec![genesis.clone()]);

    // 破坏 metadata 投影行(不影响权威源 blocks)。
    let pool = common::corrupt::connect(dsn_str).await;
    sqlx::query("DELETE FROM metadata WHERE data_id = 'm1'")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let recovery = scan_authoritative_sources_and_ensure_projections(&chain, &storage)
        .await
        .unwrap();
    assert!(
        recovery
            .projection_report
            .rebuilt_tables
            .contains(&"metadata".to_string()),
        "got: {:?}",
        recovery.projection_report.rebuilt_tables
    );
    assert_eq!(storage.metadata_projection_count().await.unwrap(), 1);
}

/// aggregations 坏 JSON:启动扫描 fail-closed,key=summary_id,且在任何写操作之前
/// (pending 重复行仍在,未被去重删除)。
#[tokio::test]
async fn startup_scan_fails_closed_on_corrupt_aggregation_before_any_write() {
    use chrono::Utc;
    use datachain::aggregation::AggregationSummary;
    use datachain::cli::server::scan_authoritative_sources_and_ensure_projections;
    use datachain::core::MetadataEntry;
    use datachain::error::{CorruptionCategory, DataChainError};

    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let dsn_str = dsn.to_str().unwrap();
    let storage = create_storage(dsn_str).await.unwrap();
    let chain = create_chain(1, 100);
    let genesis = chain.init();
    storage.save_block(&genesis).await.unwrap();

    let entry = MetadataEntry {
        data_id: "dup-1".to_string(),
        data_size: 1,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        owner: "alice".to_string(),
        hashes: std::collections::HashMap::new(),
        metadata: std::collections::HashMap::new(),
        parent_id: None,
        tags: Vec::new(),
    };
    storage.save_pending_metadata(&entry).await.unwrap();

    let summary = AggregationSummary {
        summary_id: "agg-bad".to_string(),
        summary_type: "manual".to_string(),
        level: 1,
        created_at: Utc::now(),
        time_range: None,
        block_range: Some((0, 1)),
        statistics: std::collections::HashMap::new(),
        merkle_root: "root".to_string(),
        metadata_count: 1,
        parent_summaries: Vec::new(),
        is_merged: false,
    };
    storage.save_aggregation(&summary).await.unwrap();

    let pool = common::corrupt::connect(dsn_str).await;
    sqlx::query("UPDATE aggregations SET data = ? WHERE summary_id = ?")
        .bind("{not valid json")
        .bind("agg-bad")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = match scan_authoritative_sources_and_ensure_projections(&chain, &storage).await {
        Ok(_) => panic!("aggregations 损坏必须 fail-closed"),
        Err(e) => e,
    };
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "aggregations");
            assert_eq!(key, "agg-bad");
            assert!(reason.starts_with("json_"));
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }

    // 扫描阶段未写库:pending 行仍在。
    assert_eq!(storage.get_pending_metadata().await.unwrap().len(), 1);
}
