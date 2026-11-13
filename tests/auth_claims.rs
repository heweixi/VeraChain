//! S2:Claims.sid 与登录建会话的行为测试(经 HTTP login 与 AuthService 公开方法)。

mod common;

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use common::*;
use datachain::api;
use datachain::auth::{JwtHandler, Role};
use tower::ServiceExt;

async fn login_json(router: axum::Router, username: &str, password: &str) -> serde_json::Value {
    let resp = router
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            serde_json::json!({"username": username, "password": password}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "登录应成功");
    body_json(resp).await
}

#[tokio::test]
async fn login_issues_access_token_bound_to_a_persisted_session() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let auth = state.auth_service.clone();
    let user_id = auth.get_user("alice").unwrap().user_id;
    let router = api::create_router(state);

    let json = login_json(router, "alice", "alicepass123").await;
    let token = json["data"]["token"].as_str().unwrap();
    let refresh = json["data"]["refresh_token"].as_str().unwrap();

    let claims = auth.validate_token(token).unwrap();
    let sid = claims
        .sid
        .clone()
        .expect("新签发的 access token 必须带 sid");

    let session = storage
        .get_session(&sid)
        .await
        .unwrap()
        .expect("sid 对应的会话必须已落库");
    assert_eq!(session.user_id, user_id);
    assert!(session.revoked_at.is_none());
    assert!(!session.refresh_family.is_empty());
    assert!(session.expires_at > chrono::Utc::now().timestamp());

    // 会话的 refresh_family 与刷新令牌所属 family 一致。
    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let refresh_claims = jwt.parse_refresh_claims(refresh).unwrap();
    assert_eq!(refresh_claims.family_id, session.refresh_family);

    let active = storage
        .list_active_sessions(&user_id, chrono::Utc::now().timestamp())
        .await
        .unwrap();
    assert_eq!(active.len(), 1);
}

#[tokio::test]
async fn each_login_creates_a_distinct_session() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let auth = state.auth_service.clone();
    let user_id = auth.get_user("alice").unwrap().user_id;
    let router = api::create_router(state);

    let first = login_json(router.clone(), "alice", "alicepass123").await;
    let second = login_json(router, "alice", "alicepass123").await;
    let sid1 = auth
        .validate_token(first["data"]["token"].as_str().unwrap())
        .unwrap()
        .sid
        .unwrap();
    let sid2 = auth
        .validate_token(second["data"]["token"].as_str().unwrap())
        .unwrap()
        .sid
        .unwrap();
    assert_ne!(sid1, sid2);

    let active = storage
        .list_active_sessions(&user_id, chrono::Utc::now().timestamp())
        .await
        .unwrap();
    assert_eq!(active.len(), 2);
}

#[tokio::test]
async fn session_stores_sanitized_user_agent_and_hashed_ip_only() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let auth = state.auth_service.clone();
    let router = api::create_router(state);

    // UA 含控制字符(HTTP 头只允许制表符)且超长,应去控制字符并截断到 200 字符。
    let long_ua = format!("agent\t-{}", "x".repeat(400));
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .header("user-agent", long_ua.as_bytes())
        .body(axum::body::Body::from(
            serde_json::json!({"username": "alice", "password": "alicepass123"}).to_string(),
        ))
        .unwrap();
    let peer: SocketAddr = "203.0.113.9:44321".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let sid = auth
        .validate_token(json["data"]["token"].as_str().unwrap())
        .unwrap()
        .sid
        .unwrap();
    let session = storage.get_session(&sid).await.unwrap().unwrap();

    let ua = session.user_agent.expect("应记录 user_agent");
    assert!(ua.chars().count() <= 200, "user_agent 应截断到 200 字符");
    assert!(
        !ua.chars().any(|c| c.is_control()),
        "user_agent 不得含控制字符"
    );
    assert!(ua.starts_with("agent"));

    let ip_hash = session.ip_hash.expect("有 ConnectInfo 时应记录 ip_hash");
    assert_eq!(ip_hash.len(), 32, "取 HMAC 前 16 字节的十六进制");
    assert!(ip_hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!ip_hash.contains('.'), "不得存明文 IP");
}

#[tokio::test]
async fn failed_login_creates_no_session() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let user_id = state.auth_service.get_user("alice").unwrap().user_id;
    let router = api::create_router(state);

    let resp = router
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            serde_json::json!({"username": "alice", "password": "wrong-password"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(storage
        .list_active_sessions(&user_id, chrono::Utc::now().timestamp())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn legacy_access_token_without_sid_still_validates_and_authorizes() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _storage) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let auth = state.auth_service.clone();
    let user = auth.get_user("alice").unwrap();
    let router = api::create_router(state);

    // 手工构造不含 sid 字段的旧格式 access token。
    let now = chrono::Utc::now().timestamp();
    let legacy_claims = serde_json::json!({
        "sub": user.user_id,
        "username": "alice",
        "role": "user",
        "exp": now + 3600,
        "iat": now,
        "iss": "datachain",
        "aud": "datachain-api",
    });
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &legacy_claims,
        &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap();

    let claims = auth.validate_token(&token).unwrap();
    assert!(claims.sid.is_none());

    let resp = router
        .oneshot(get("/api/v1/auth/profile", Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
