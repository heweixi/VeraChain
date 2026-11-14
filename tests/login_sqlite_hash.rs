//! C2(B11a):login 以 SQLite 中的密码哈希与活跃状态为准的行为测试。
//!
//! 公开 seam:HTTP login(router oneshot)+ 独立 sqlx 连接直接改库(模拟另一进程,
//! 例如 CLI 改密/删用户,运行中服务的内存哈希保持旧值,不经 AuthService)。
//! 审计经 `Storage::list_audit_events` 读取。
//!
//! 实现前预期 Red:当前 login 按内存 `User.password_hash` 验密,
//! 用例 1(新密码 200/旧密码 401)与用例 2(删行后 401 且 reason `unknown user`)应失败;
//! 用例 3 为回归,应保持通过。

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::Role;
use serde_json::{json, Value};
use tower::ServiceExt;

const P_OLD: &str = "alicepass123";
const P_NEW: &str = "brand-new-pass-456";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

/// 每个用例只建一次 build_state(同 DSN 重复建会重复写创世块)。
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("sqlhash.db").to_str().unwrap().to_string();
    let (state, _) = build_state(&dsn).await;
    seed_user(&state, "alice", P_OLD, Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

impl Fixture {
    async fn login(&self, username: &str, password: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                None,
                json!({"username": username, "password": password}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    fn alice_id(&self) -> String {
        self.state.auth_service.get_user("alice").unwrap().user_id
    }
}

#[tokio::test]
async fn login_uses_password_hash_from_sqlite_not_memory() {
    let f = fixture().await;
    let alice_id = f.alice_id();

    // 另一进程改库:内存里的哈希仍是 P_OLD 的。低 cost 加快测试,bcrypt 验证按哈希内置 cost。
    let new_hash = bcrypt::hash(P_NEW, 4).unwrap();
    let pool = common::corrupt::connect(&f.dsn).await;
    sqlx::query("UPDATE users SET password_hash = ? WHERE user_id = ?")
        .bind(&new_hash)
        .bind(&alice_id)
        .execute(&pool)
        .await
        .unwrap();

    let (status_new, _) = f.login("alice", P_NEW).await;
    assert_eq!(status_new, StatusCode::OK, "库里的新哈希应让新密码登录成功");

    let (status_old, _) = f.login("alice", P_OLD).await;
    assert_eq!(
        status_old,
        StatusCode::UNAUTHORIZED,
        "库里已换哈希,旧密码应被拒绝"
    );
}

#[tokio::test]
async fn login_treats_user_missing_in_sqlite_as_unknown_user() {
    let f = fixture().await;
    let alice_id = f.alice_id();

    // 另一进程删除用户行:内存仍有 alice,但以 SQLite 为权威,应按未知用户处理。
    let pool = common::corrupt::connect(&f.dsn).await;
    sqlx::query("DELETE FROM users WHERE user_id = ?")
        .bind(&alice_id)
        .execute(&pool)
        .await
        .unwrap();

    let (status, _) = f.login("alice", P_OLD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let events = f.state.storage.list_audit_events(1000).await.unwrap();
    let failures: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "login_failure")
        .collect();
    assert_eq!(failures.len(), 1, "应恰好写一行 login_failure");
    assert_eq!(failures[0].reason.as_deref(), Some("unknown user"));
}

#[tokio::test]
async fn login_without_db_change_still_works() {
    let f = fixture().await;

    let (status_ok, body) = f.login("alice", P_OLD).await;
    assert_eq!(status_ok, StatusCode::OK);
    assert!(body["data"]["token"].as_str().is_some());

    let (status_bad, _) = f.login("alice", "wrong-password-xyz").await;
    assert_eq!(status_bad, StatusCode::UNAUTHORIZED);
}
