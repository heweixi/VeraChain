//! S4:ConnectInfo 与全局限流的行为测试。
//! 真实监听 127.0.0.1:0(经 `api::make_service`,与 run_server 两条路径同一转换),
//! 以及无 ConnectInfo 的 oneshot 回退。
mod common;
use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use datachain::api::{self, RateLimiter};
use datachain::auth::Role;
use tower::ServiceExt;

async fn start_real_server(dir: &tempfile::TempDir) -> (SocketAddr, datachain::api::AppState) {
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    let app = api::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, api::make_service(app)).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, state)
}

async fn refresh_with_xff(client: &reqwest::Client, addr: SocketAddr, xff: &str) -> StatusCode {
    let resp = client
        .post(format!("http://{}/api/v1/auth/refresh", addr))
        .header("x-forwarded-for", xff)
        .header("x-real-ip", xff)
        .json(&serde_json::json!({"refresh_token": "garbage"}))
        .send()
        .await
        .unwrap();
    StatusCode::from_u16(resp.status().as_u16()).unwrap()
}

#[tokio::test]
async fn rotating_x_forwarded_for_does_not_escape_the_auth_rate_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _) = start_real_server(&dir).await;
    let client = reqwest::Client::new();
    for i in 0..20 {
        let status = refresh_with_xff(&client, addr, &format!("198.51.100.{}", i)).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "第 {} 次不应限流",
            i + 1
        );
    }
    // 第 21 次换了全新的 XFF,仍应落入同一个对端地址的桶而被限流。
    let status = refresh_with_xff(&client, addr, "203.0.113.200").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn health_is_exempt_from_rate_limit_on_real_server() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _) = start_real_server(&dir).await;
    let client = reqwest::Client::new();
    for i in 0..130 {
        let resp = client
            .get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "第 {} 次 /health 应豁免限流", i + 1);
    }
}

#[tokio::test]
async fn login_session_records_hash_of_real_peer_ip_on_real_server() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, state) = start_real_server(&dir).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/auth/login", addr))
        .header("x-forwarded-for", "198.51.100.77")
        .json(&serde_json::json!({"username": "alice", "password": "alicepass123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let claims = state
        .auth_service
        .validate_token(body["data"]["token"].as_str().unwrap())
        .unwrap();
    let session = state
        .storage
        .get_session(&claims.sid.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        session.ip_hash.as_deref(),
        Some(state.auth_service.hash_client_ip("127.0.0.1").as_str()),
        "应记录真实对端 127.0.0.1 的摘要,而非 XFF 或占位"
    );
}

#[tokio::test]
async fn oneshot_without_connect_info_ignores_forged_xff_and_shares_one_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    let router = api::create_router(state);
    for i in 0..21 {
        let mut req = post(
            "/api/v1/auth/refresh",
            None,
            serde_json::json!({"refresh_token": "garbage"}),
        );
        req.headers_mut().insert(
            "x-forwarded-for",
            format!("198.51.100.{}", i).parse().unwrap(),
        );
        let status = router.clone().oneshot(req).await.unwrap().status();
        if i < 20 {
            assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "第 {} 次", i + 1);
        } else {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "回退占位桶应被限流");
        }
    }
}

#[tokio::test]
async fn expired_rate_limit_entries_are_evicted() {
    let limiter = RateLimiter::new(120, 20, Duration::from_millis(50));
    for i in 0..500 {
        assert!(limiter.allow(&format!("forged-{}", i), false));
    }
    assert!(limiter.tracked_keys() >= 500);
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(limiter.allow("fresh", false));
    assert!(
        limiter.tracked_keys() <= 10,
        "过期 key 应被淘汰,实际仍有 {}",
        limiter.tracked_keys()
    );
}
