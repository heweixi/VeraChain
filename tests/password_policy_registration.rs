//! C3(B12):注册与 CLI 创建用户的密码策略行为测试。
//!
//! 公开 seam:
//! - HTTP `POST /api/v1/auth/register`(router oneshot)+ `POST /api/v1/auth/login`;
//! - 真实二进制 `datachain user create --username .. --password .. --email ..`(同一 SQLite 文件);
//! - 库内状态经公开的 `Storage::get_all_users` 观察。
//!
//! 实现前预期 Red 原因:当前 `register` / CLI `create` 走 `register_with_role`,不校验密码策略
//! (短密码、过长、含 NUL 都被接受),并发同名注册可能多个成功,CLI 失败也返回退出码 0。
//! 8 字符合法密码用例为回归,应保持通过。
mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{create_auth_service_with_settings, AuthSettings, Role};
use datachain::storage::Storage;
use serde_json::{json, Value};
use tower::ServiceExt;

struct Fixture {
    router: Router,
    state: AppState,
    storage: Arc<Storage>,
    dsn: String,
    _dir: tempfile::TempDir,
}

/// 每个用例只建一次 build_state(同 DSN 重复建会重复写创世块)。
/// `min_len` 为 Some 时用 `create_auth_service_with_settings` 覆盖 password_min_length。
async fn fixture(min_len: Option<usize>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("pwpolicy.db").to_str().unwrap().to_string();
    let (mut state, storage) = build_state(&dsn).await;
    if let Some(n) = min_len {
        state.auth_service = create_auth_service_with_settings(
            JWT_SECRET.to_string(),
            storage.clone(),
            AuthSettings {
                password_min_length: n,
                ..AuthSettings::default()
            },
        );
    }
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        storage,
        dsn,
        _dir: dir,
    }
}

async fn register_via(router: &Router, username: &str, password: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(post(
            "/api/v1/auth/register",
            None,
            json!({
                "username": username,
                "password": password,
                "email": format!("{}@test.local", username),
            }),
        ))
        .await
        .unwrap();
    (resp.status(), body_json(resp).await)
}

async fn login_via(router: &Router, username: &str, password: &str) -> StatusCode {
    router
        .clone()
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            json!({"username": username, "password": password}),
        ))
        .await
        .unwrap()
        .status()
}

impl Fixture {
    async fn register(&self, username: &str, password: &str) -> (StatusCode, Value) {
        register_via(&self.router, username, password).await
    }

    async fn login(&self, username: &str, password: &str) -> StatusCode {
        login_via(&self.router, username, password).await
    }

    async fn count_users_named(&self, username: &str) -> usize {
        self.storage
            .get_all_users()
            .await
            .unwrap()
            .iter()
            .filter(|u| u.username == username)
            .count()
    }

    async fn run_cli(&self, args: &[&str]) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args(["--config", "/nonexistent/datachain-test.toml"])
            .args(args)
            .env("DATACHAIN_JWT_SECRET", JWT_SECRET)
            .env("DATACHAIN_DATABASE_DSN", &self.dsn)
            .output()
            .await
            .unwrap()
    }

    async fn cli_create(
        &self,
        username: &str,
        password: &str,
        email: &str,
    ) -> std::process::Output {
        self.run_cli(&[
            "user",
            "create",
            "--username",
            username,
            "--password",
            password,
            "--email",
            email,
        ])
        .await
    }
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

// ---------------------------------------------------------------- HTTP

#[tokio::test]
async fn register_rejects_password_shorter_than_default_minimum() {
    let f = fixture(None).await;
    let (status, body) = f.register("bob", "1234567").await; // 7 字符
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={}", body);
    assert_eq!(body["success"], false);
    assert_eq!(body["error"], "password too short");

    assert_eq!(
        f.login("bob", "1234567").await,
        StatusCode::UNAUTHORIZED,
        "被拒的用户不应能登录"
    );
    assert_eq!(f.count_users_named("bob").await, 0, "库里不应有该用户");
}

#[tokio::test]
async fn register_rejects_password_longer_than_72_bytes() {
    let f = fixture(None).await;
    let long = "a".repeat(73);
    let (status, body) = f.register("bob", &long).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={}", body);
    assert_eq!(body["error"], "password too long");
    assert_eq!(f.count_users_named("bob").await, 0);

    // 边界:恰好 72 字节仍合法。
    let (status, body) = f.register("carol", &"a".repeat(72)).await;
    assert_eq!(status, StatusCode::CREATED, "body={}", body);
}

#[tokio::test]
async fn register_rejects_password_with_nul() {
    let f = fixture(None).await;
    let (status, body) = f.register("bob", "pass\0word123").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={}", body);
    assert_eq!(body["error"], "password contains invalid characters");
    assert_eq!(f.count_users_named("bob").await, 0);
}

#[tokio::test]
async fn register_accepts_eight_char_password_and_user_can_login() {
    let f = fixture(None).await;
    let (status, body) = f.register("bob", "12345678").await; // 恰好 8 字符
    assert_eq!(status, StatusCode::CREATED, "body={}", body);
    assert_eq!(body["data"]["username"], "bob");
    assert_eq!(f.login("bob", "12345678").await, StatusCode::OK);
    assert_eq!(f.count_users_named("bob").await, 1);
}

#[tokio::test]
async fn register_honors_configured_password_min_length() {
    let f = fixture(Some(10)).await;
    let (status, body) = f.register("bob", "123456789").await; // 9 字符
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={}", body);
    assert_eq!(body["error"], "password too short");
    assert_eq!(f.count_users_named("bob").await, 0);

    let (status, body) = f.register("bob", "1234567890").await; // 10 字符
    assert_eq!(status, StatusCode::CREATED, "body={}", body);
    assert_eq!(f.login("bob", "1234567890").await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_register_same_username_creates_exactly_one_user() {
    let f = fixture(None).await;
    let mut handles = Vec::new();
    for i in 0..8 {
        let router = f.router.clone();
        let password = format!("password-{}-xyz", i);
        handles.push(tokio::spawn(async move {
            let resp = router
                .oneshot(post(
                    "/api/v1/auth/register",
                    None,
                    json!({
                        "username": "racer",
                        "password": password,
                        "email": format!("racer{}@test.local", i),
                    }),
                ))
                .await
                .unwrap();
            (i, resp.status())
        }));
    }
    let mut winners = Vec::new();
    let mut others = Vec::new();
    for h in handles {
        let (i, status) = h.await.unwrap();
        if status == StatusCode::CREATED {
            winners.push(i);
        } else {
            others.push(status);
        }
    }
    assert_eq!(winners.len(), 1, "恰好 1 个 201,实际 winners={:?}", winners);
    assert_eq!(others.len(), 7);
    assert!(
        others.iter().all(|s| *s == StatusCode::BAD_REQUEST),
        "其余应为 400: {:?}",
        others
    );

    assert_eq!(
        f.count_users_named("racer").await,
        1,
        "库里只应有一个同名用户"
    );
    assert_eq!(
        f.state
            .auth_service
            .get_all_users()
            .iter()
            .filter(|u| u.username == "racer")
            .count(),
        1,
        "内存用户表只应有一个同名用户"
    );
    let winner_password = format!("password-{}-xyz", winners[0]);
    assert_eq!(
        f.login("racer", &winner_password).await,
        StatusCode::OK,
        "创建成功的用户必须可登录(索引未被后续失败请求破坏)"
    );
}

// ---------------------------------------------------------------- CLI

#[tokio::test]
async fn cli_create_rejects_short_password_with_nonzero_exit() {
    let f = fixture(None).await;
    let out = f.cli_create("bob", "1234567", "bob@test.local").await;
    assert!(
        !out.status.success(),
        "短密码应非 0 退出; stdout={} stderr={}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert_eq!(f.count_users_named("bob").await, 0, "库里不应有该用户");
}

#[tokio::test]
async fn cli_create_duplicate_username_exits_nonzero() {
    let f = fixture(None).await;
    let out = f
        .cli_create("alice", "another-pass-123", "alice2@test.local")
        .await;
    assert!(
        !out.status.success(),
        "重复用户名应非 0 退出; stdout={} stderr={}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert_eq!(f.count_users_named("alice").await, 1, "原用户保持唯一");
}

#[tokio::test]
async fn cli_create_valid_user_exits_zero_and_persists() {
    let f = fixture(None).await;
    let out = f.cli_create("bob", "12345678", "bob@test.local").await;
    assert!(
        out.status.success(),
        "合法用户应退出 0; stdout={} stderr={}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert_eq!(f.count_users_named("bob").await, 1, "库里应有该用户");
}
