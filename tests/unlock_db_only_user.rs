//! C3(B15):unlock 对"库里有、内存无"的用户可用(TDD Red)。
//!
//! 公开 seam:`POST /api/v1/admin/users/:user_id/unlock`、`Storage::get_login_lock`、
//! `Storage::list_audit_events`。
//!
//! "库里有、内存无"的构造:先经 `seed_user` 注册并 `save_user` 落库,取得 user_id 后
//! 用 `AuthService::remove_user` 只从内存用户表移除,库里的行保留。
//! 再用 `lock_login_key` 与 `incr_login_counter` 写入该用户 `user:<用户名>` key 的锁行与计数行。
//!
//! 实现前预期 Red:`unlock_user` 只查内存用户表,对 carol 返回 `UserNotFound`,
//! HTTP 为 404,用例 1 失败;用例 2、3 当前已通过(未知用户 404、内存用户解锁 200)。
//!
//! 时钟:限速是 epoch 对齐的固定窗口,固定存储时钟取真实时间对齐到窗口整数倍再 +10 秒,
//! 每个用例只算一次。每个用例只建一次 `build_state`(同 DSN 重复建会重复写创世块)。

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{AuthService, AuthSettings, Role};
use datachain::storage::{AuditEvent, Storage};
use serde_json::{json, Value};
use tower::ServiceExt;

const ROOT_PW: &str = "rootpass12345";
const ALICE_PW: &str = "alicepass123";
const CAROL_PW: &str = "carolpass1234";
const WINDOW: i64 = 900;

struct Fixture {
    router: Router,
    state: AppState,
    storage: Arc<Storage>,
    now: i64,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: StatusCode,
    body: Value,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("unlock-db-only.db").to_str().unwrap().to_string();
    let (mut state, storage) = build_state(&dsn).await;
    let pinned = (chrono::Utc::now().timestamp() / WINDOW) * WINDOW + 10;
    storage.set_clock(Arc::new(move || pinned));
    state.auth_service = Arc::new(AuthService::with_settings(
        JWT_SECRET.to_string(),
        storage.clone(),
        AuthSettings::default(),
    ));
    seed_user(&state, "root", ROOT_PW, Role::Admin).await;
    seed_user(&state, "alice", ALICE_PW, Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        storage,
        now: pinned,
        _dir: dir,
    }
}

impl Fixture {
    async fn send(&self, req: axum::http::Request<axum::body::Body>) -> Resp {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        Resp {
            status,
            body: body_json(resp).await,
        }
    }

    async fn admin_token(&self) -> String {
        let r = self
            .send(post(
                "/api/v1/auth/login",
                None,
                json!({"username": "root", "password": ROOT_PW}),
            ))
            .await;
        assert_eq!(r.status, StatusCode::OK, "管理员登录应成功: {}", r.body);
        r.body["data"]["token"].as_str().unwrap().to_string()
    }

    async fn http_unlock(&self, target: &str, token: &str) -> Resp {
        self.send(post(
            &format!("/api/v1/admin/users/{}/unlock", target),
            Some(token),
            json!({}),
        ))
        .await
    }

    fn user_id(&self, name: &str) -> String {
        self.state.auth_service.get_user(name).unwrap().user_id
    }

    /// 创建 carol:库里有行,内存没有。返回其 user_id。
    async fn seed_db_only_user(&self, name: &str) -> String {
        seed_user(&self.state, name, CAROL_PW, Role::User).await;
        let id = self.user_id(name);
        assert!(self.state.auth_service.remove_user(&id), "应从内存移除");
        assert!(
            self.state.auth_service.get_user_by_id(&id).is_err(),
            "内存里不应再有该用户"
        );
        assert!(
            self.storage
                .get_all_users()
                .await
                .unwrap()
                .iter()
                .any(|u| u.user_id == id),
            "库里应仍有该用户"
        );
        id
    }

    /// 为 `user:<name>` key 写入一条锁行和一行窗口计数。
    async fn make_lock_and_counter(&self, name: &str) -> String {
        let key = format!("user:{}", name);
        self.storage
            .lock_login_key(&key, self.now, 900, 3600, 86400)
            .await
            .unwrap();
        // lock_login_key 会清该 key 的计数,所以计数行在落锁之后写。
        self.storage
            .incr_login_counter(&key, self.now, WINDOW)
            .await
            .unwrap();
        assert!(
            self.storage
                .get_login_lock(&key, self.now)
                .await
                .unwrap()
                .is_some(),
            "前置:锁行应存在"
        );
        key
    }

    async fn events_of(&self, event_type: &str) -> Vec<AuditEvent> {
        self.storage
            .list_audit_events(1000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }
}

/// 1. 库里有、内存无:管理员 HTTP 解锁 200,锁被清,审计带 actor 与目标。
#[tokio::test]
async fn http_unlock_works_for_user_only_in_database() {
    let f = fixture().await;
    let admin = f.admin_token().await;
    let carol_id = f.seed_db_only_user("carol").await;
    let key = f.make_lock_and_counter("carol").await;

    let r = f.http_unlock(&carol_id, &admin).await;

    assert_eq!(r.status, StatusCode::OK, "库里有的用户应可解锁: {}", r.body);
    assert_eq!(r.body["data"]["unlocked"], true, "{}", r.body);
    assert_eq!(r.body["data"]["user_id"], carol_id.as_str(), "{}", r.body);
    assert_eq!(
        f.storage.get_login_lock(&key, f.now).await.unwrap(),
        None,
        "解锁后锁行应被清除"
    );

    let rows = f.events_of("login_unlocked").await;
    assert_eq!(rows.len(), 1, "应恰好一条 login_unlocked: {:?}", rows);
    let ev = &rows[0];
    assert_eq!(ev.user_id.as_deref(), Some(carol_id.as_str()));
    assert_eq!(
        ev.actor_user_id.as_deref(),
        Some(f.user_id("root").as_str()),
        "应记录管理员为操作者"
    );
    assert_eq!(ev.result, "success");
    assert_eq!(
        ev.reason.as_deref(),
        Some("cleared locks=1 counters=1"),
        "应清除 1 条锁与 1 行计数"
    );
}

/// 2. 库里也不存在:404 `user not found`,不写审计。
#[tokio::test]
async fn http_unlock_unknown_in_memory_and_database_is_404_without_audit() {
    let f = fixture().await;
    let admin = f.admin_token().await;

    let r = f.http_unlock("no-such-user-id", &admin).await;

    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    assert_eq!(r.body["error"], "user not found");
    assert!(f.events_of("login_unlocked").await.is_empty());
}

/// 3. 回归:内存里有的用户(alice)解锁仍正常。
#[tokio::test]
async fn http_unlock_still_works_for_in_memory_user() {
    let f = fixture().await;
    let admin = f.admin_token().await;
    let alice_id = f.user_id("alice");
    let key = f.make_lock_and_counter("alice").await;

    let r = f.http_unlock(&alice_id, &admin).await;

    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        r.body,
        json!({"success": true, "data": {"user_id": alice_id, "unlocked": true}})
    );
    assert_eq!(f.storage.get_login_lock(&key, f.now).await.unwrap(), None);
    assert_eq!(f.events_of("login_unlocked").await.len(), 1);
}
