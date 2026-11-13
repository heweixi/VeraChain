//! S7:CLI `user deactivate|activate <username>` 的行为测试。
//! 通过真实二进制(独立进程)写同一个 SQLite 文件,模拟运维在服务进程之外停用用户。
mod common;

use std::process::Output;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::Role;
use serde_json::json;
use tower::ServiceExt;

struct Fixture {
    router: axum::Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let (state, storage) = build_state(&dsn).await;
    // 禁用 is_active 缓存,避免测试等待 TTL。
    storage.set_active_cache_ttl(Duration::ZERO);
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

impl Fixture {
    async fn run_cli(&self, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args(["--config", "/nonexistent/datachain-test.toml"])
            .args(args)
            .env("DATACHAIN_JWT_SECRET", JWT_SECRET)
            .env("DATACHAIN_DATABASE_DSN", &self.dsn)
            .output()
            .await
            .unwrap()
    }

    async fn login(&self) -> (StatusCode, serde_json::Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                None,
                json!({"username": "alice", "password": "alicepass123"}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn profile(&self, token: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(get("/api/v1/auth/profile", Some(token)))
            .await
            .unwrap()
            .status()
    }
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

#[tokio::test]
async fn cli_deactivate_revokes_sessions_and_blocks_protected_api() {
    let f = fixture().await;
    let (status, body) = f.login().await;
    assert_eq!(status, StatusCode::OK);
    let access = body["data"]["token"].as_str().unwrap().to_string();
    let refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
    let sid = f
        .state
        .auth_service
        .validate_token(&access)
        .unwrap()
        .sid
        .unwrap();
    assert_eq!(f.profile(&access).await, StatusCode::OK);

    let out = f.run_cli(&["user", "deactivate", "alice"]).await;
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        text(&out.stdout),
        text(&out.stderr)
    );

    assert_eq!(
        f.profile(&access).await,
        StatusCode::UNAUTHORIZED,
        "CLI 停用后受保护接口应变 401"
    );
    let user_id = f.state.auth_service.get_user("alice").unwrap().user_id;
    assert!(!f.state.storage.is_user_active(&user_id).await.unwrap());
    let session = f.state.storage.get_session(&sid).await.unwrap().unwrap();
    assert!(session.revoked_at.is_some(), "CLI 应撤销该用户全部会话");
    let resp = f
        .router
        .clone()
        .oneshot(post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": refresh}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.login().await.0, StatusCode::UNAUTHORIZED);

    let events = f.state.storage.list_audit_events(100).await.unwrap();
    let deactivated: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "user_deactivated")
        .collect();
    assert_eq!(deactivated.len(), 1, "CLI 停用应写审计");
    assert_eq!(deactivated[0].user_id.as_deref(), Some(user_id.as_str()));
}

#[tokio::test]
async fn cli_activate_restores_login_but_not_old_sessions() {
    let f = fixture().await;
    let (_, body) = f.login().await;
    let old_access = body["data"]["token"].as_str().unwrap().to_string();
    let user_id = f.state.auth_service.get_user("alice").unwrap().user_id;

    // 运行中的服务先把用户停用(内存与 SQLite 同步),再由 CLI 在服务之外重新启用。
    f.state
        .auth_service
        .deactivate_user(&user_id)
        .await
        .unwrap();
    assert_eq!(f.login().await.0, StatusCode::UNAUTHORIZED);

    let out = f.run_cli(&["user", "activate", "alice"]).await;
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        text(&out.stdout),
        text(&out.stderr)
    );

    assert!(f.state.storage.is_user_active(&user_id).await.unwrap());
    assert_eq!(
        f.profile(&old_access).await,
        StatusCode::UNAUTHORIZED,
        "activate 不恢复已撤销的旧会话"
    );
    let (status, body) = f.login().await;
    assert_eq!(status, StatusCode::OK, "启用后应能重新登录: {}", body);
    let new_access = body["data"]["token"].as_str().unwrap();
    assert_eq!(f.profile(new_access).await, StatusCode::OK);

    let events = f.state.storage.list_audit_events(100).await.unwrap();
    assert!(events.iter().any(|e| e.event_type == "user_activated"));
}

#[tokio::test]
async fn cli_reports_unknown_user_with_nonzero_exit() {
    let f = fixture().await;
    for action in ["deactivate", "activate"] {
        let out = f.run_cli(&["user", action, "ghost"]).await;
        assert!(!out.status.success(), "{} 不存在的用户应返回非 0", action);
        let combined = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(
            combined.contains("ghost"),
            "错误信息应指出用户名: {}",
            combined
        );
    }
    let events = f.state.storage.list_audit_events(100).await.unwrap();
    assert!(events.is_empty());
}
