//! A2:login / refresh 遇存储故障或数据损坏时必须返回 500,
//! body 固定为 `internal error`,且不泄露表名/列名/key/SQL/password_hash。
//!
//! 经公开 seam:HTTP router oneshot;故障由独立连接直接破坏 SQLite 注入。
mod common;

use axum::http::StatusCode;
use common::*;
use datachain::api;
use datachain::auth::Role;
use serde_json::{json, Value};
use tower::ServiceExt;

struct Fixture {
    router: axum::Router,
    dsn: String,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let (state, _) = build_state(&dsn).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    Fixture {
        router: api::create_router(state),
        dsn,
        _dir: dir,
    }
}

impl Fixture {
    async fn sql(&self, sql: &str) {
        let pool = corrupt::connect(&self.dsn).await;
        corrupt::execute_sql(&pool, sql).await;
        pool.close().await;
    }

    async fn login(&self, password: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                None,
                json!({"username": "alice", "password": password}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn refresh(&self, token: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": token}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn login_ok(&self) -> String {
        let (status, body) = self.login("alicepass123").await;
        assert_eq!(status, StatusCode::OK);
        body["data"]["refresh_token"].as_str().unwrap().to_string()
    }
}

/// 500 响应必须是固定的 `internal error`,不含任何内部细节。
fn assert_opaque_internal_error(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], "internal error");
    let text = body.to_string().to_lowercase();
    for forbidden in [
        "login_rate_counters",
        "sessions",
        "revoked_refresh_tokens",
        "users",
        "password_hash",
        "refresh_family",
        "no such table",
        "select ",
        "insert ",
        "column",
        "sqlite",
        "alice",
    ] {
        assert!(
            !text.contains(forbidden),
            "500 响应泄露了 `{}`: {}",
            forbidden,
            text
        );
    }
}

#[tokio::test]
async fn login_returns_500_when_rate_counter_table_is_gone() {
    let f = fixture().await;
    f.sql("DROP TABLE login_rate_counters").await;
    let (status, body) = f.login("alicepass123").await;
    assert_opaque_internal_error(status, &body);
}

#[tokio::test]
async fn login_returns_500_when_sessions_table_is_gone() {
    let f = fixture().await;
    f.sql("DROP TABLE sessions").await;
    let (status, body) = f.login("alicepass123").await;
    assert_opaque_internal_error(status, &body);
}

#[tokio::test]
async fn login_returns_500_when_user_is_active_column_is_undecodable() {
    let f = fixture().await;
    f.sql("UPDATE users SET is_active = 'garbage'").await;
    let (status, body) = f.login("alicepass123").await;
    assert_opaque_internal_error(status, &body);
}

#[tokio::test]
async fn login_wrong_password_stays_401_not_500_with_healthy_storage() {
    let f = fixture().await;
    let (status, body) = f.login("wrong-password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid credentials");
}

#[tokio::test]
async fn refresh_returns_500_when_revoked_tokens_table_is_gone() {
    let f = fixture().await;
    let refresh = f.login_ok().await;
    f.sql("DROP TABLE revoked_refresh_tokens").await;
    let (status, body) = f.refresh(&refresh).await;
    assert_opaque_internal_error(status, &body);
}

#[tokio::test]
async fn refresh_returns_500_when_session_row_is_undecodable() {
    let f = fixture().await;
    let refresh = f.login_ok().await;
    f.sql("UPDATE sessions SET created_at = 'not-an-int'").await;
    let (status, body) = f.refresh(&refresh).await;
    assert_opaque_internal_error(status, &body);
}

#[tokio::test]
async fn refresh_with_garbage_token_stays_401_not_500() {
    let f = fixture().await;
    let (status, _) = f.refresh("definitely-not-a-jwt").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
